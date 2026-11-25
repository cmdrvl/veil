#![cfg(feature = "proptest")]

use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;
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

struct Fixture {
    root: PathBuf,
    seatbelt: seatbelt::CompiledProfile,
    landlock: landlock::CompiledRuleset,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();

    FIXTURE.get_or_init(|| {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after the epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "veil-formal-properties-{}-{timestamp}",
            std::process::id()
        ));
        for name in ["protected", "private", "public", "vault"] {
            fs::create_dir_all(root.join(name)).expect("fixture directory should be created");
        }

        let config = config(
            vec!["protected/**".to_owned(), "private/**".to_owned()],
            vec!["*.csv".to_owned(), "*.txt".to_owned()],
            vec!["shape".to_owned(), "rvl".to_owned(), "profile".to_owned()],
        );
        let seatbelt = seatbelt::compile(&config, &root).expect("Seatbelt profile should compile");
        let landlock =
            landlock::compile(&config, &root, &root).expect("Landlock rules should compile");

        Fixture {
            root,
            seatbelt,
            landlock,
        }
    })
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
            audit_log: false,
            audit_path: PathBuf::from("/unused/veil-formal-properties-audit.jsonl"),
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
        protected_dir in prop_oneof![Just("protected"), Just("private")],
        nested_dir in "[a-z]{1,10}",
        basename in "[a-z]{1,10}",
        safe_and_extension in prop_oneof![Just(("*.csv", "csv")), Just(("*.txt", "txt"))],
        extra_protected_dir in "[a-z]{1,10}",
        authorized_tool in prop_oneof![Just("shape"), Just("rvl"), Just("profile")],
    ) {
        let fixture = fixture();
        let (safe_pattern, extension) = safe_and_extension;
        let path = fixture
            .root
            .join(protected_dir)
            .join(nested_dir)
            .join(format!("{basename}.{extension}"));
        let safe_matcher = SafePathMatcher::from_patterns([safe_pattern]);
        prop_assert!(safe_matcher.is_safe(&path), "the generated safe glob must match");

        let mut active_config = config(
            vec!["protected/**".to_owned(), "private/**".to_owned()],
            vec![safe_pattern.to_owned()],
            vec![authorized_tool.to_owned()],
        );
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

        let protected_root = fixture.root.join(protected_dir);
        let seatbelt_rule = format!(
            "(deny file-read* (subpath \"{}\"))",
            protected_root.display()
        );
        prop_assert!(fixture.seatbelt.profile.contains(&seatbelt_rule));
        prop_assert!(fixture.landlock.excluded.contains(&protected_root));
        prop_assert!(
            !fixture
                .landlock
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
