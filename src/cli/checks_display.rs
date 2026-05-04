//! Shared display utilities for doctor/status check output.
//!
//! Maps integrity `CheckItem.category` strings to doctor's 4-section model.
//! Status retains its own legacy formatter (v0.10.0 compat).

use crate::integrity::CheckItem;

/// Doctor's 4-section model (Layer 1 / Layer 2 / Integrity / Risk signals).
/// Risk signals come from `audit::report`, not from integrity checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DoctorSection {
    Layer1,
    Layer2,
    Integrity,
}

impl DoctorSection {
    pub fn heading(self) -> &'static str {
        match self {
            Self::Layer1 => "[Layer 1] PATH shims",
            Self::Layer2 => "[Layer 2] Hook defense",
            Self::Integrity => "[Integrity] Config & baseline",
        }
    }
}

/// Deterministic mapping from CheckItem.category to DoctorSection.
///
/// Categories are fixed strings from integrity.rs:
/// Shims, Hooks, Config, Core Policy, PATH, Baseline
pub fn map_category_to_section(category: &str) -> DoctorSection {
    match category {
        "Shims" | "PATH" => DoctorSection::Layer1,
        "Hooks" => DoctorSection::Layer2,
        "Config" | "Core Policy" | "Baseline" => DoctorSection::Integrity,
        _ => DoctorSection::Integrity,
    }
}

/// Group CheckItems by DoctorSection, preserving order within each group.
pub fn group_by_section(items: &[CheckItem]) -> [(DoctorSection, Vec<&CheckItem>); 3] {
    let mut layer1 = Vec::new();
    let mut layer2 = Vec::new();
    let mut integrity = Vec::new();

    for item in items {
        match map_category_to_section(item.category) {
            DoctorSection::Layer1 => layer1.push(item),
            DoctorSection::Layer2 => layer2.push(item),
            DoctorSection::Integrity => integrity.push(item),
        }
    }

    [
        (DoctorSection::Layer1, layer1),
        (DoctorSection::Layer2, layer2),
        (DoctorSection::Integrity, integrity),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integrity::{CheckItem, CheckStatus};

    #[test]
    fn test_category_mapping() {
        assert_eq!(map_category_to_section("Shims"), DoctorSection::Layer1);
        assert_eq!(map_category_to_section("PATH"), DoctorSection::Layer1);
        assert_eq!(map_category_to_section("Hooks"), DoctorSection::Layer2);
        assert_eq!(map_category_to_section("Config"), DoctorSection::Integrity);
        assert_eq!(
            map_category_to_section("Core Policy"),
            DoctorSection::Integrity
        );
        assert_eq!(
            map_category_to_section("Baseline"),
            DoctorSection::Integrity
        );
        assert_eq!(map_category_to_section("Unknown"), DoctorSection::Integrity);
    }

    #[test]
    fn test_group_by_section_preserves_order() {
        let items = vec![
            CheckItem {
                category: "Shims",
                name: "cp".to_string(),
                status: CheckStatus::Ok,
                detail: "ok".to_string(),
                remediation: None,
            },
            CheckItem {
                category: "Shims",
                name: "rm".to_string(),
                status: CheckStatus::Fail,
                detail: "missing".to_string(),
                remediation: None,
            },
            CheckItem {
                category: "Shims",
                name: "mv".to_string(),
                status: CheckStatus::Ok,
                detail: "ok".to_string(),
                remediation: None,
            },
        ];
        let groups = group_by_section(&items);
        let names: Vec<&str> = groups[0].1.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, vec!["cp", "rm", "mv"]);
    }

    #[test]
    fn test_unknown_categories_land_in_integrity() {
        let items = vec![
            CheckItem {
                category: "FutureCategory",
                name: "a".to_string(),
                status: CheckStatus::Ok,
                detail: "ok".to_string(),
                remediation: None,
            },
            CheckItem {
                category: "",
                name: "b".to_string(),
                status: CheckStatus::Ok,
                detail: "ok".to_string(),
                remediation: None,
            },
        ];
        let groups = group_by_section(&items);
        assert!(groups[0].1.is_empty(), "Layer1 should be empty");
        assert!(groups[1].1.is_empty(), "Layer2 should be empty");
        assert_eq!(groups[2].1.len(), 2, "both unknowns should land in Integrity");
    }

    #[test]
    fn test_group_by_section() {
        let items = vec![
            CheckItem {
                category: "Shims",
                name: "rm".to_string(),
                status: CheckStatus::Ok,
                detail: "ok".to_string(),
                remediation: None,
            },
            CheckItem {
                category: "Hooks",
                name: "hook1".to_string(),
                status: CheckStatus::Ok,
                detail: "ok".to_string(),
                remediation: None,
            },
            CheckItem {
                category: "Config",
                name: "cfg".to_string(),
                status: CheckStatus::Ok,
                detail: "ok".to_string(),
                remediation: None,
            },
        ];
        let groups = group_by_section(&items);
        assert_eq!(groups[0].0, DoctorSection::Layer1);
        assert_eq!(groups[0].1.len(), 1);
        assert_eq!(groups[1].0, DoctorSection::Layer2);
        assert_eq!(groups[1].1.len(), 1);
        assert_eq!(groups[2].0, DoctorSection::Integrity);
        assert_eq!(groups[2].1.len(), 1);
    }
}
