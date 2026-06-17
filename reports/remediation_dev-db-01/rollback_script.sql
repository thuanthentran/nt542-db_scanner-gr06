-- ROLLBACK SCRIPT GENERATED ON 2026-05-21 16:13:43.153895
-- Chạy script này để khôi phục trạng thái trước khi Remediation

-- Rollback for Rule 2.13
ALTER LOGIN sa ENABLE;

-- Rollback for Rule 4.2
ALTER LOGIN [sa] WITH CHECK_EXPIRATION = OFF;
ALTER LOGIN [remediation_login] WITH CHECK_EXPIRATION = OFF;

