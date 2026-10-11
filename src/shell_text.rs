use std::ops::Range;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Heredoc {
    pub(crate) operator: Range<usize>,
    pub(crate) body: Range<usize>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
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
    let mut stack: Vec<Ctx> = Vec::new();
    let mut pending: Vec<Pending> = Vec::new();
    let mut found = Vec::new();
    let mut word_start = true;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let next = bytes.get(i + 1).copied();
        let top = stack.last().copied();
        match top {
            Some(Ctx::Single) => {
                if b == b'\'' {
                    stack.pop();
                }
                i += 1;
                continue;
            }
            Some(Ctx::AnsiC) | Some(Ctx::Backtick) => {
                let close = if top == Some(Ctx::AnsiC) { b'\'' } else { b'`' };
                if b == b'\\' {
                    i += 2;
                } else {
                    if b == close {
                        stack.pop();
                    }
                    i += 1;
                }
                continue;
            }
            Some(Ctx::Double) => {
                match b {
                    b'\\' => i += 2,
                    b'"' => {
                        stack.pop();
                        i += 1;
                    }
                    b'$' if next == Some(b'\'') => i += 1,
                    b'$' | b'`' => i = open_expansion(bytes, i, &mut stack),
                    _ => i += 1,
                }
                continue;
            }
            Some(Ctx::Arith) if b == b')' && next == Some(b')') => {
                stack.pop();
                i += 2;
                continue;
            }
            Some(Ctx::Param) if b == b'}' => {
                stack.pop();
                i += 1;
                continue;
            }
            Some(Ctx::Bracket) if b == b']' => {
                stack.pop();
                i += 1;
                continue;
            }
            _ => {}
        }

        match b {
            b'\\' => {
                if next == Some(b'\n') && !pending.is_empty() {
                    return None;
                }
                i += 2;
                word_start = false;
            }
            b'\'' => {
                stack.push(Ctx::Single);
                i += 1;
                word_start = false;
            }
            b'"' => {
                stack.push(Ctx::Double);
                i += 1;
                word_start = false;
            }
            b'$' | b'`' => {
                i = open_expansion(bytes, i, &mut stack);
                word_start = false;
            }
            b'(' => {
                if word_start && next == Some(b'(') {
                    stack.push(Ctx::Arith);
                    i += 2;
                } else {
                    stack.push(Ctx::Group);
                    i += 1;
                }
                word_start = true;
            }
            b')' => {
                if !matches!(top, Some(Ctx::Subst) | Some(Ctx::Group)) {
                    return None;
                }
                stack.pop();
                i += 1;
                word_start = true;
            }
            b'#' if word_start && !matches!(top, Some(Ctx::Arith) | Some(Ctx::Param)) => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'<' if next == Some(b'<') => {
                if bytes.get(i + 2) == Some(&b'<') {
                    i += 3;
                    word_start = true;
                    continue;
                }
                if matches!(
                    top,
                    Some(Ctx::Arith) | Some(Ctx::Param) | Some(Ctx::Bracket)
                ) {
                    i += 2;
                    continue;
                }
                // Not followed: where the body of a heredoc inside a
                // substitution or a group ends, so none is certain.
                if top.is_some() {
                    return None;
                }
                let (delimiter, quoted, strip_tabs, end) = read_operator(bytes, i)?;
                pending.push(Pending {
                    operator: i..end,
                    delimiter,
                    strip_tabs,
                    quoted,
                });
                i = end;
                word_start = true;
            }
            b'\n' => {
                i += 1;
                word_start = true;
                if top.is_none() && !pending.is_empty() {
                    i = read_bodies(text, i, &mut pending, &mut found)?;
                }
            }
            _ => {
                word_start = matches!(b, b' ' | b'\t' | b';' | b'&' | b'|' | b'<' | b'>');
                i += 1;
            }
        }
    }
    (stack.is_empty() && pending.is_empty()).then_some(found)
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
}
