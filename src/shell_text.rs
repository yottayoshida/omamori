use std::borrow::Cow;
use std::ops::Range;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Heredoc {
    pub(crate) operator: Range<usize>,
    pub(crate) body: Range<usize>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Ctx {
    Single,
    Double,
    AnsiC,
    Backtick,
    Subst,
    Group,
    Arith,
    Param,
    Bracket,
    // In `[[ … ]]` a `(` is not a group, nor a `#` a comment.
    Cond,
}

enum Step {
    Next(usize),
    Comment(usize),
    Heredoc,
    NestedHeredoc,
    TopNewline,
    Continuation,
    Unbalanced,
}

struct Tracker {
    stack: Vec<Ctx>,
    word_start: bool,
}

impl Tracker {
    fn new() -> Self {
        Self {
            stack: Vec::new(),
            word_start: true,
        }
    }

    fn top(&self) -> Option<Ctx> {
        self.stack.last().copied()
    }

    fn close(&mut self) {
        self.stack.pop();
        self.word_start = false;
    }

    // A `$'…'` inside another quote is not rewritten: the word splitter does
    // not nest quotes.
    fn outside_splitter_quotes(&self) -> bool {
        !self
            .stack
            .iter()
            .any(|c| matches!(c, Ctx::Single | Ctx::Double | Ctx::AnsiC))
    }

    fn step(&mut self, bytes: &[u8], i: usize) -> Step {
        let b = bytes[i];
        let next = bytes.get(i + 1).copied();
        let top = self.top();
        match top {
            Some(Ctx::Single) => {
                if b == b'\'' {
                    self.close();
                }
                return Step::Next(i + 1);
            }
            Some(Ctx::AnsiC) | Some(Ctx::Backtick) => {
                let close = if top == Some(Ctx::AnsiC) { b'\'' } else { b'`' };
                if b == b'\\' {
                    return Step::Next(i + 2);
                }
                if b == close {
                    self.close();
                }
                return Step::Next(i + 1);
            }
            Some(Ctx::Double) => {
                return match b {
                    b'\\' => Step::Next(i + 2),
                    b'"' => {
                        self.close();
                        Step::Next(i + 1)
                    }
                    b'$' if next == Some(b'\'') => Step::Next(i + 1),
                    b'$' | b'`' => Step::Next(open_expansion(bytes, i, &mut self.stack)),
                    _ => Step::Next(i + 1),
                };
            }
            Some(Ctx::Arith) if b == b')' && next == Some(b')') => {
                self.close();
                return Step::Next(i + 2);
            }
            Some(Ctx::Param) if b == b'}' => {
                self.close();
                return Step::Next(i + 1);
            }
            Some(Ctx::Bracket) if b == b']' => {
                self.close();
                return Step::Next(i + 1);
            }
            Some(Ctx::Cond) if b == b']' && next == Some(b']') => {
                self.close();
                return Step::Next(i + 2);
            }
            Some(Ctx::Cond) if matches!(b, b'(' | b')' | b'#') => {
                self.word_start = false;
                return Step::Next(i + 1);
            }
            _ => {}
        }

        match b {
            // A `\` and a newline vanish in the shell, and the word state
            // before them carries on; any other escape is part of a word.
            b'\\' if next == Some(b'\n') => {
                if top.is_none() {
                    Step::Continuation
                } else {
                    Step::Next(i + 2)
                }
            }
            b'\\' => {
                self.word_start = false;
                Step::Next(i + 2)
            }
            b'[' if self.word_start && next == Some(b'[') => {
                self.stack.push(Ctx::Cond);
                Step::Next(i + 2)
            }
            b'\'' => {
                self.stack.push(Ctx::Single);
                self.word_start = false;
                Step::Next(i + 1)
            }
            b'"' => {
                self.stack.push(Ctx::Double);
                self.word_start = false;
                Step::Next(i + 1)
            }
            b'$' | b'`' => {
                self.word_start = false;
                Step::Next(open_expansion(bytes, i, &mut self.stack))
            }
            b'(' => {
                let arith = self.word_start && next == Some(b'(');
                self.stack.push(if arith { Ctx::Arith } else { Ctx::Group });
                self.word_start = true;
                Step::Next(i + if arith { 2 } else { 1 })
            }
            b')' => match top {
                // After a group the shell begins a new word; after a
                // substitution the word goes on (`$(date)#x` is one word).
                Some(Ctx::Group) => {
                    self.stack.pop();
                    self.word_start = true;
                    Step::Next(i + 1)
                }
                Some(Ctx::Subst) => {
                    self.close();
                    Step::Next(i + 1)
                }
                _ => {
                    self.word_start = true;
                    Step::Unbalanced
                }
            },
            b'#' if self.word_start && !matches!(top, Some(Ctx::Arith) | Some(Ctx::Param)) => {
                let end = bytes[i..]
                    .iter()
                    .position(|&c| c == b'\n')
                    .map_or(bytes.len(), |n| i + n);
                Step::Comment(end)
            }
            b'<' if next == Some(b'<') => {
                self.word_start = true;
                if bytes.get(i + 2) == Some(&b'<') {
                    Step::Next(i + 3)
                } else if matches!(
                    top,
                    Some(Ctx::Arith) | Some(Ctx::Param) | Some(Ctx::Bracket)
                ) {
                    Step::Next(i + 2)
                } else if top.is_none() {
                    Step::Heredoc
                } else {
                    Step::NestedHeredoc
                }
            }
            b'\n' => {
                self.word_start = true;
                if top.is_none() {
                    Step::TopNewline
                } else {
                    Step::Next(i + 1)
                }
            }
            _ => {
                self.word_start = matches!(b, b' ' | b'\t' | b';' | b'&' | b'|' | b'<' | b'>');
                Step::Next(i + 1)
            }
        }
    }
}

struct Pending {
    operator: Range<usize>,
    delimiter: String,
    strip_tabs: bool,
    quoted: bool,
}

// Not one body at a time: the shell reads bodies one after another, so one
// unsure body makes every body unsure.
pub(crate) fn certain_heredocs(text: &str) -> Option<Vec<Heredoc>> {
    let bytes = text.as_bytes();
    let mut tracker = Tracker::new();
    let mut pending: Vec<Pending> = Vec::new();
    let mut found = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match tracker.step(bytes, i) {
            Step::Next(n) | Step::Comment(n) => i = n,
            Step::Heredoc => {
                let (delimiter, quoted, strip_tabs, end) = read_operator(bytes, i)?;
                pending.push(Pending {
                    operator: i..end,
                    delimiter,
                    strip_tabs,
                    quoted,
                });
                i = end;
            }
            // Not followed: where a heredoc's body ends inside a substitution or
            // a group, or after a `)` that closes nothing, so none is certain.
            Step::NestedHeredoc | Step::Unbalanced => return None,
            Step::Continuation => {
                if !pending.is_empty() {
                    return None;
                }
                i += 2;
            }
            Step::TopNewline => {
                i += 1;
                if !pending.is_empty() {
                    i = read_bodies(text, i, &mut pending, &mut found)?;
                }
            }
        }
    }
    (tracker.stack.is_empty() && pending.is_empty()).then_some(found)
}

// Not the shell's quoting: normalize and the word splitter know `'`, `"` and
// `$'…'` with `\` escapes, never nested.
struct PlainQuotes {
    single: bool,
    double: bool,
    ansi: bool,
    escaped: bool,
    after_dollar: bool,
    between_words: bool,
}

impl PlainQuotes {
    fn new() -> Self {
        Self {
            single: false,
            double: false,
            ansi: false,
            escaped: false,
            after_dollar: false,
            between_words: true,
        }
    }

    fn comment_starts_here(&self) -> bool {
        !self.single && !self.double && !self.ansi && !self.escaped && self.between_words
    }

    fn advance(&mut self, c: u8) {
        if self.escaped {
            self.escaped = false;
            self.after_dollar = false;
            // A `\` and a newline vanish; the word state before them holds.
            if c != b'\n' {
                self.between_words = false;
            }
            return;
        }
        if self.single {
            self.single = c != b'\'';
            return;
        }
        if self.ansi || self.double {
            match c {
                b'\\' => self.escaped = true,
                b'\'' if self.ansi => self.ansi = false,
                b'"' if self.double => self.double = false,
                _ => {}
            }
            return;
        }
        if c == b'\\' {
            self.escaped = true;
            self.after_dollar = false;
            return;
        }
        match c {
            b'\'' if self.after_dollar => self.ansi = true,
            b'\'' => self.single = true,
            b'"' => self.double = true,
            _ => {}
        }
        self.after_dollar = c == b'$';
        self.between_words = c.is_ascii_whitespace() || matches!(c, b';' | b'|' | b'&');
    }
}

// Never removes anything, only adds a `\`: a misreading here then makes more
// of the text visible, never less.
pub(crate) fn protect_hashes(text: &str) -> Cow<'_, str> {
    if !text.contains('#') {
        return Cow::Borrowed(text);
    }
    let bytes = text.as_bytes();
    let mut tracker = Tracker::new();
    let mut plain = PlainQuotes::new();
    let mut pending: Vec<Pending> = Vec::new();
    let mut out: Vec<u8> = Vec::with_capacity(text.len() + 8);
    let mut changed = false;
    let mut i = 0;
    let copy = |out: &mut Vec<u8>, plain: &mut PlainQuotes, from: usize, to: usize| {
        for &c in &bytes[from..to] {
            plain.advance(c);
            out.push(c);
        }
    };
    while i < bytes.len() {
        let in_shell = matches!(tracker.top(), None | Some(Ctx::Subst) | Some(Ctx::Group));
        if bytes[i] == b'\n' && in_shell && !pending.is_empty() {
            tracker.step(bytes, i);
            copy(&mut out, &mut plain, i, i + 1);
            i += 1;
            match read_bodies(text, i, &mut pending, &mut Vec::new()) {
                Some(end) => {
                    copy(&mut out, &mut plain, i, end);
                    i = end;
                }
                None => break,
            }
            continue;
        }
        let next = match tracker.step(bytes, i) {
            Step::Next(n) => {
                for &c in &bytes[i..n.min(bytes.len())] {
                    if c == b'#' && plain.comment_starts_here() {
                        out.push(b'\\');
                        changed = true;
                    }
                    plain.advance(c);
                    out.push(c);
                }
                i = n.min(bytes.len());
                continue;
            }
            Step::Comment(end) => end,
            Step::Heredoc | Step::NestedHeredoc => match read_operator(bytes, i) {
                Some((delimiter, quoted, strip_tabs, end)) => {
                    pending.push(Pending {
                        operator: i..end,
                        delimiter,
                        strip_tabs,
                        quoted,
                    });
                    end
                }
                None => break,
            },
            Step::Continuation => i + 2,
            Step::TopNewline => i + 1,
            Step::Unbalanced => break,
        };
        let next = next.min(bytes.len());
        copy(&mut out, &mut plain, i, next);
        i = next;
    }
    if !changed {
        return Cow::Borrowed(text);
    }
    out.extend_from_slice(&bytes[i.min(bytes.len())..]);
    Cow::Owned(
        String::from_utf8(out)
            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()),
    )
}

// Escapes are kept as written except `\'`: it would end no string in `"…"`.
pub(crate) fn ansi_c_as_double_quoted(text: &str) -> Cow<'_, str> {
    if !text.contains("$'") {
        return Cow::Borrowed(text);
    }
    let bytes = text.as_bytes();
    let mut tracker = Tracker::new();
    let mut out: Vec<u8> = Vec::with_capacity(text.len() + 8);
    let mut i = 0;
    while i < bytes.len() {
        let opening_ansi = bytes[i] == b'$'
            && bytes.get(i + 1) == Some(&b'\'')
            && tracker.outside_splitter_quotes()
            && tracker.top() != Some(Ctx::Backtick);
        let next = match tracker.step(bytes, i) {
            Step::Next(n) | Step::Comment(n) => n,
            Step::Heredoc | Step::NestedHeredoc | Step::Continuation => i + 2,
            Step::TopNewline | Step::Unbalanced => i + 1,
        };
        if !opening_ansi {
            out.extend_from_slice(&bytes[i..next.min(bytes.len())]);
            i = next;
            continue;
        }
        out.push(b'"');
        let mut j = i + 2;
        while j < bytes.len() && bytes[j] != b'\'' {
            match bytes[j] {
                b'\\' if bytes.get(j + 1) == Some(&b'\'') => {
                    out.push(b'\'');
                    j += 2;
                    continue;
                }
                b'\\' => {
                    out.extend_from_slice(&bytes[j..(j + 2).min(bytes.len())]);
                    j += 2;
                    continue;
                }
                b'"' | b'$' | b'`' => {
                    out.push(b'\\');
                    out.push(bytes[j]);
                }
                c => out.push(c),
            }
            j += 1;
        }
        out.push(b'"');
        i = (j + 1).min(bytes.len());
        tracker.stack.pop();
    }
    Cow::Owned(
        String::from_utf8(out)
            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()),
    )
}

fn open_expansion(bytes: &[u8], i: usize, stack: &mut Vec<Ctx>) -> usize {
    if bytes[i] == b'`' {
        stack.push(Ctx::Backtick);
        return i + 1;
    }
    match (bytes.get(i + 1), bytes.get(i + 2)) {
        (Some(b'('), Some(b'(')) => {
            stack.push(Ctx::Arith);
            i + 3
        }
        (Some(b'('), _) => {
            stack.push(Ctx::Subst);
            i + 2
        }
        (Some(b'{'), _) => {
            stack.push(Ctx::Param);
            i + 2
        }
        (Some(b'['), _) => {
            stack.push(Ctx::Bracket);
            i + 2
        }
        (Some(b'\''), _) => {
            stack.push(Ctx::AnsiC);
            i + 2
        }
        _ => i + 1,
    }
}

fn read_operator(bytes: &[u8], i: usize) -> Option<(String, bool, bool, usize)> {
    let mut j = i + 2;
    let strip_tabs = bytes.get(j) == Some(&b'-');
    if strip_tabs {
        j += 1;
    }
    while matches!(bytes.get(j), Some(b' ' | b'\t')) {
        j += 1;
    }
    let (word, quoted, end) = match bytes.get(j) {
        Some(&quote @ (b'\'' | b'"')) => {
            let close = bytes[j + 1..].iter().position(|&c| c == quote)? + j + 1;
            (&bytes[j + 1..close], true, close + 1)
        }
        _ => {
            let len = bytes[j..]
                .iter()
                .take_while(|c| c.is_ascii_alphanumeric() || **c == b'_')
                .count();
            (&bytes[j..j + len], false, j + len)
        }
    };
    let identifier = word
        .first()
        .is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_')
        && word.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_');
    let boundary = matches!(
        bytes.get(end),
        None | Some(b' ' | b'\t' | b'\n' | b';' | b'&' | b'|' | b'<' | b'>' | b')')
    );
    (identifier && boundary).then(|| {
        (
            String::from_utf8_lossy(word).into_owned(),
            quoted,
            strip_tabs,
            end,
        )
    })
}

// A body that continues a line with `\` under an unquoted delimiter is not
// certain: the shell joins those lines before it compares them with the
// delimiter.
fn read_bodies(
    text: &str,
    start: usize,
    pending: &mut Vec<Pending>,
    found: &mut Vec<Heredoc>,
) -> Option<usize> {
    let mut pos = start;
    for heredoc in pending.drain(..) {
        let body_start = pos;
        loop {
            if pos >= text.len() {
                return None;
            }
            let line_end = text[pos..].find('\n').map_or(text.len(), |n| pos + n);
            let line = &text[pos..line_end];
            let after = (line_end + 1).min(text.len());
            let compared = if heredoc.strip_tabs {
                line.trim_start_matches('\t')
            } else {
                line
            };
            if compared == heredoc.delimiter {
                found.push(Heredoc {
                    operator: heredoc.operator,
                    body: body_start..after,
                });
                pos = after;
                break;
            }
            if !heredoc.quoted && line.ends_with('\\') {
                return None;
            }
            pos = after;
        }
    }
    Some(pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bodies(text: &str) -> Option<Vec<&str>> {
        certain_heredocs(text).map(|found| found.iter().map(|h| &text[h.body.clone()]).collect())
    }

    #[test]
    fn a_closed_heredoc_with_a_plain_delimiter_is_certain() {
        assert_eq!(
            bodies("cat > f <<'EOF'\na\nb\nEOF\necho done"),
            Some(vec!["a\nb\nEOF\n"])
        );
        assert_eq!(bodies("cat <<EOF\nx\nEOF"), Some(vec!["x\nEOF"]));
        assert_eq!(bodies("cat <<\"EOF\"\nx\nEOF\n"), Some(vec!["x\nEOF\n"]));
        assert_eq!(
            bodies("cat <<-EOF\n\tx\n\tEOF\n"),
            Some(vec!["\tx\n\tEOF\n"])
        );
    }

    #[test]
    fn two_heredocs_on_one_line_are_read_in_order() {
        assert_eq!(
            bodies("bash <<B; cat <<A\nb1\nB\na1\nA\n"),
            Some(vec!["b1\nB\n", "a1\nA\n"])
        );
    }

    #[test]
    fn text_without_a_heredoc_has_none() {
        assert_eq!(bodies("echo hi; cat <<< word"), Some(vec![]));
    }

    #[test]
    fn a_shift_inside_an_expansion_is_not_a_heredoc() {
        assert_eq!(bodies("echo $((1<<2))\nls"), Some(vec![]));
        assert_eq!(bodies("cat /dev/null ${x:1<<1}\nls\n1}"), Some(vec![]));
        assert_eq!(bodies("cat /dev/null $[1<<2]\nls\n2]"), Some(vec![]));
    }

    #[test]
    fn a_heredoc_in_a_comment_is_not_one() {
        assert_eq!(bodies("cat /dev/null # see <<EOF\nls\nEOF"), Some(vec![]));
        assert_eq!(bodies("echo a#b <<EOF\nx\nEOF"), Some(vec!["x\nEOF"]));
    }

    #[test]
    fn a_heredoc_whose_extent_is_unsure_makes_the_whole_text_unsure() {
        for text in [
            "cat <<EOF\nnever closed",
            "cat <<EOF\nb\nE\\\nOF\nls\nEOF",
            "cat <<EOF \\\n| sh\nls\nEOF",
            "cat <<2))\nls",
            "cat <<E'O'F\nx\nEOF",
            "x=$(cat <<EOF\ny\nEOF\n)",
            "(cat <<EOF\nx\nEOF\n)",
            "cat <<EOF\nx\nEOF\r\n",
            "echo )",
            "echo 'unclosed",
        ] {
            assert_eq!(bodies(text), None, "{text:?}");
        }
    }

    #[test]
    fn a_quoted_delimiter_keeps_a_trailing_backslash_as_text() {
        assert_eq!(bodies("cat <<'EOF'\na\\\nEOF\n"), Some(vec!["a\\\nEOF\n"]));
    }

    #[test]
    fn quotes_and_expansions_hide_what_looks_like_an_operator() {
        assert_eq!(bodies("echo '<<EOF'\nls"), Some(vec![]));
        assert_eq!(bodies("echo \"a <<EOF\"\nls"), Some(vec![]));
        assert_eq!(bodies("echo $'\\' <<EOF'\nls"), Some(vec![]));
        assert_eq!(
            bodies("echo \"$(date)\" <<EOF\nx\nEOF\n"),
            Some(vec!["x\nEOF\n"])
        );
    }

    #[test]
    fn non_ascii_text_is_read_by_byte_without_losing_its_place() {
        assert_eq!(
            bodies("cat <<EOF\n日本語\nEOF\n"),
            Some(vec!["日本語\nEOF\n"])
        );
    }

    #[test]
    fn a_hash_the_shell_reads_inside_a_word_gets_a_backslash() {
        for (text, expected) in [
            ("echo `echo a #b` ; ls", "echo `echo a \\#b` ; ls"),
            ("echo $((1 + #x)) ; ls", "echo $((1 + \\#x)) ; ls"),
            ("[[ $x =~ ( #a) ]] ; ls", "[[ $x =~ ( \\#a) ]] ; ls"),
            (
                "msg=\"$(git log -1 --format=\"%s #%h\")\" ; ls",
                "msg=\"$(git log -1 --format=\"%s \\#%h\")\" ; ls",
            ),
        ] {
            assert_eq!(protect_hashes(text), expected, "{text:?}");
        }
    }

    #[test]
    fn a_comment_or_a_hash_inside_a_word_is_left_alone() {
        for text in [
            "# note\ngit push",
            "ls # a ; b\nrm x",
            "echo a#b",
            "echo ${#a[@]}",
            "echo $(date)#x ; ls",
            "diff <(true)#x ; ls",
            "a=(1 2)#x ; ls",
            "echo '# x' \"# y\"",
            "echo $'a # b' ; ls",
            "x=$(echo a # c\n)",
            "ls \\\n# cleanup ; rm x",
        ] {
            assert_eq!(protect_hashes(text), text, "{text:?}");
        }
    }

    #[test]
    fn a_heredoc_body_in_a_substitution_is_read_past() {
        let text = "git commit -m \"$(cat <<'EOF'\nit's\nEOF\n)\" ; echo `a #b`";
        assert_eq!(
            protect_hashes(text),
            "git commit -m \"$(cat <<'EOF'\nit's\nEOF\n)\" ; echo `a \\#b`"
        );
    }

    #[test]
    fn nothing_is_escaped_past_what_cannot_be_followed() {
        assert_eq!(
            protect_hashes("echo ) ; echo `a #b`"),
            "echo ) ; echo `a #b`"
        );
        assert_eq!(
            protect_hashes("cat <<2))\nx\n2))\necho `a #b`"),
            "cat <<2))\nx\n2))\necho `a #b`"
        );
    }

    #[test]
    fn an_ansi_c_string_becomes_a_double_quoted_one() {
        assert_eq!(
            ansi_c_as_double_quoted("echo $'a\\'b'; ls"),
            "echo \"a'b\"; ls"
        );
        assert_eq!(
            ansi_c_as_double_quoted("echo $'$x \"q\"'"),
            "echo \"\\$x \\\"q\\\"\""
        );
        assert_eq!(ansi_c_as_double_quoted("echo '$'\"$'\""), "echo '$'\"$'\"");
        let nested = "git commit -m \"$(printf $'a ; b')\"";
        assert_eq!(ansi_c_as_double_quoted(nested), nested);
        assert_eq!(
            shell_words::split(&ansi_c_as_double_quoted("echo $'\\' # ' ; git push")).unwrap(),
            vec!["echo", "' # ", ";", "git", "push"]
        );
    }
}
