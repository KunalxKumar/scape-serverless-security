# SCAPE Recovery Evaluation Summary

| Experiment | Domain | Split | Tau | TP | FP | FN | TN | Precision | Recall | F1 | Accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| E1_baseline_hard_veto | all | file | 0.0100 | 40 | 90 | 0 | 0 | 30.77% | 100.00% | 47.06% | 30.77% |
| E2_mitigated_mixed_domain | all | file | 0.0600 | 20 | 0 | 20 | 90 | 100.00% | 50.00% | 66.67% | 84.62% |
| E3_mitigated_synthetic_domain | synthetic | file | 0.0600 | 20 | 0 | 20 | 90 | 100.00% | 50.00% | 66.67% | 84.62% |

## Interpretation
- E1 reproduces the mixed-domain collapse pattern (all events blocked).
- E2 mitigates collapse and restores benign acceptance on mixed-domain data.
- E3 preserves mitigation under a domain-consistent (synthetic) configuration.