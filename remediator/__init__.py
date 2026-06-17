from .surface_area import fix_sys_config, fix_rule_2_9, fix_rule_2_13
from .password_policies import fix_rule_4_2, fix_rule_4_3

# Khai báo các Rule có thể Auto-remediate
REMEDIATION_REGISTRY = {
    "2.1": lambda cursor: fix_sys_config(cursor, "2.1", "Ad Hoc Distributed Queries", 0),
    "2.2": lambda cursor: fix_sys_config(cursor, "2.2", "clr enabled", 0),
    "2.3": lambda cursor: fix_sys_config(cursor, "2.3", "cross db ownership chaining", 0),
    "2.4": lambda cursor: fix_sys_config(cursor, "2.4", "Database Mail XPs", 0),
    "2.5": lambda cursor: fix_sys_config(cursor, "2.5", "Ole Automation Procedures", 0),
    "2.6": lambda cursor: fix_sys_config(cursor, "2.6", "remote access", 0),
    "2.8": lambda cursor: fix_sys_config(cursor, "2.8", "scan for startup procs", 0),
    "2.17": lambda cursor: fix_sys_config(cursor, "2.17", "clr strict security", 1),
    "2.9": fix_rule_2_9,
    "2.13": fix_rule_2_13,
    "4.2": fix_rule_4_2,
    "4.3": fix_rule_4_3,
    # Module Auditing:
    "5.2": lambda cursor: fix_sys_config(cursor, "5.2", "default trace enabled", 1)
}