#![cfg(feature = "proptest")]

use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use proptest::prelude::*;
use veil::allowlist::SafePathMatcher;
use veil::config::{
    AllowlistConfig, Config, DynamicArgsMode, McpConfig, PolicyConfig, PolicyMode,
    SensitivityConfig, SpineConfig,
};
use veil::evaluator::{EvaluationInput, evaluate_access};
use veil::extract::{PathExposure, decompose};
use veil::packs::PackRegistry;
use veil::protected_corpus::CorpusLimits;
use veil::sandbox::{landlock, seatbelt};
use veil::spine::DeniedFlags;
use veil::types::{AccessAssessment, Clearance, DecisionAction, InformationLabel, ToolKind};

/// A new, empty project directory for one generated case. Each case has its own,
/// so what a compiler finds on disk is only what that case's config is about.
fn case_root() -> PathBuf {
    static RUN: OnceLock<PathBuf> = OnceLock::new();
    static CASE: AtomicUsize = AtomicUsize::new(0);

    let run = RUN.get_or_init(|| {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after the epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "veil-formal-properties-{}-{timestamp}",
            std::process::id()
        ))
    });
    let root = run.join(CASE.fetch_add(1, Ordering::Relaxed).to_string());
    fs::create_dir_all(&root).expect("case directory should be created");
    fs::canonicalize(root).expect("case directory should canonicalize")
}

fn config(
    protected: Vec<String>,
    safe_patterns: Vec<String>,
    authorized_tools: Vec<String>,
) -> Config {
    Config {
        sensitivity: SensitivityConfig { protected },
        allowlist: AllowlistConfig { safe_patterns },
        spine: SpineConfig {
            authorized_tools,
            denied_flags: DeniedFlags::default(),
        },
        policy: PolicyConfig {
            default: PolicyMode::Deny,
            egress: Some(PolicyMode::Warn),
            audit_log: false,
            audit_path: PathBuf::from("/unused/veil-formal-properties-audit.jsonl"),
            audit_inputs: false,
            require_dcg: false,
            dynamic_args: DynamicArgsMode::Deny,
        },
        protected_corpus: CorpusLimits::default(),
        mcp: McpConfig::default(),
    }
}

fn label_strategy() -> impl Strategy<Value = InformationLabel> {
    prop_oneof![
        Just(InformationLabel::Public),
        Just(InformationLabel::Derived),
        Just(InformationLabel::Protected),
    ]
}

fn clearance_strategy() -> impl Strategy<Value = Clearance> {
    prop_oneof![
        Just(Clearance::Public),
        Just(Clearance::Derived),
        Just(Clearance::Protected),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 512,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn label_join_is_commutative_associative_and_idempotent(
        left in label_strategy(),
        middle in label_strategy(),
        right in label_strategy(),
    ) {
        prop_assert_eq!(left.join(middle), middle.join(left));
        prop_assert_eq!(left.join(left), left);
        prop_assert_eq!(left.join(middle).join(right), left.join(middle.join(right)));
    }

    #[test]
    fn clearance_admits_only_labels_at_or_below_it(
        clearance in clearance_strategy(),
        label in label_strategy(),
    ) {
        let expected = match clearance {
            Clearance::Public => label == InformationLabel::Public,
            Clearance::Derived => label != InformationLabel::Protected,
            Clearance::Protected => true,
        };
        prop_assert_eq!(clearance.admits(label), expected);
    }

    #[test]
    fn hook_denials_dominate_both_compiled_read_profiles(
        protected_dirs in prop::collection::btree_set("vault-[a-z]{1,10}", 1..4),
        chosen in any::<prop::sample::Index>(),
        nested_dir in "[a-z]{1,10}",
        basename in "[a-z]{1,10}",
        safe_and_extension in prop_oneof![Just(("*.csv", "csv")), Just(("*.txt", "txt"))],
        extra_protected_dir in "[a-z]{1,10}",
        authorized_tool in prop_oneof![Just("shape"), Just("rvl"), Just("profile")],
    ) {
        let root = case_root();
        for directory in &protected_dirs {
            fs::create_dir(root.join(directory)).expect("protected directory");
        }
        let protected: Vec<String> = protected_dirs
            .iter()
            .map(|directory| format!("{directory}/**"))
            .collect();
        let protected_dir = chosen.get(&protected_dirs.into_iter().collect::<Vec<_>>()).clone();
        let (safe_pattern, extension) = safe_and_extension;
        let path = root
            .join(&protected_dir)
            .join(nested_dir)
            .join(format!("{basename}.{extension}"));
        let safe_matcher = SafePathMatcher::from_patterns([safe_pattern]);
        prop_assert!(safe_matcher.is_safe(&path), "the generated safe glob must match");

        let mut active_config = config(
            protected,
            vec![safe_pattern.to_owned()],
            vec![authorized_tool.to_owned()],
        );
        // both profiles are compiled from the config the hook judges with
        let seatbelt = seatbelt::compile(&active_config, &root).expect("Seatbelt profile");
        let landlock = landlock::compile(&active_config, &root, &root).expect("Landlock rules");
        let registry = PackRegistry::with_built_ins();
        let hook_decision = evaluate_access(
            &EvaluationInput::new(ToolKind::Read, path.clone(), PathExposure::ReadsContents),
            &active_config,
            &registry,
        );
        prop_assert_eq!(
            hook_decision.assessment(),
            AccessAssessment::new(
                InformationLabel::Protected,
                Clearance::Derived,
                DecisionAction::Deny,
            ),
        );

        let protected_root = root.join(&protected_dir);
        let seatbelt_rule = format!(
            "(deny file-read* (subpath \"{}\"))",
            protected_root.display()
        );
        prop_assert!(seatbelt.profile.contains(&seatbelt_rule));
        prop_assert!(landlock.excluded.contains(&protected_root));
        prop_assert!(
            !landlock
                .allowed
                .iter()
                .any(|hierarchy| hierarchy.path.starts_with(&protected_root))
        );

        active_config
            .sensitivity
            .protected
            .push(format!("{extra_protected_dir}/**"));
        let after_adding_protection = evaluate_access(
            &EvaluationInput::new(ToolKind::Read, path, PathExposure::ReadsContents),
            &active_config,
            &registry,
        );
        prop_assert_eq!(after_adding_protection.action, DecisionAction::Deny);
    }

    #[test]
    fn normalized_simple_command_decomposition_is_idempotent(
        directory in "[a-z]{1,10}",
        basename in "[a-z]{1,10}",
        extension in prop_oneof![Just("csv"), Just("txt")],
    ) {
        let command = format!("cat {directory}/{basename}.{extension}");
        let once = decompose(&command);
        let normalized = once
            .iter()
            .map(|segment| segment.argv.join(" "))
            .collect::<Vec<_>>()
            .join("; ");
        prop_assert_eq!(decompose(&normalized), once);
    }
}
