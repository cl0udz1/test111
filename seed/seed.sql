-- Deterministic seed for Raqeem HelpDesk workshop
-- NOTE: This file intentionally contains NO flag. The flag is provisioned
-- at runtime by the Worker (see src/index.ts ensureRuntimeSeed) into ticket 15.
-- TARGET_ID=14 must exist from this seed. Ticket 15 is the private victim ticket.
-- Passwords are strong pre-hashed PBKDF2 values (see README for reset instructions).

INSERT OR IGNORE INTO users (id, name, email, password_hash, created_at) VALUES
(1, 'Layla Ahmed', 'layla.ahmed@raqeem-tech.com', 'pbkdf2$100000$a1b2c3d4e5f60718293a4b5c6d7e8f90$2eab0a2c7c19bc37ebe6bb3d92119f7639bc02a111c7504c8929975a676f623e', '2026-01-05 09:00:00'),
(2, 'Support Agent', 'support@raqeem-tech.com', 'pbkdf2$100000$0f1e2d3c4b5a69788796a5b4c3d2e1f0$8065bb646fd3a89f25c908d2272da05192513663184166feae07225bc01123a4', '2026-01-05 09:00:00');

-- Reset autoincrement counters so future user tickets start at 16+
-- (D1/SQLite sqlite_sequence handling is done implicitly by explicit IDs.)

INSERT OR IGNORE INTO tickets (id, user_id, title, category, priority, status, description, created_at, updated_at) VALUES
(1, 1, 'Email sync issue - Outlook', 'Software', 'Medium', 'resolved', 'Outlook on my laptop stopped syncing since Monday. I tried restarting but new emails do not arrive until I click Send/Receive manually.', '2026-01-06 10:00:00', '2026-01-07 14:00:00'),
(2, 1, 'Laptop running very slow', 'Hardware', 'Medium', 'in_progress', 'My Dell Latitude takes 10+ minutes to boot and Teams freezes during calls. Please check if RAM upgrade is possible.', '2026-01-08 11:30:00', '2026-01-09 09:15:00'),
(3, 1, 'VPN disconnects frequently', 'Network', 'High', 'open', 'VPN client disconnects every 15-20 minutes when working from home. Internet is stable, only VPN drops.', '2026-01-10 08:45:00', '2026-01-10 08:45:00'),
(4, 1, 'Request new keyboard', 'Hardware', 'Low', 'closed', 'Spacebar on my keyboard is stuck. Can I get a replacement Arabic/English keyboard?', '2026-01-11 13:00:00', '2026-01-12 10:00:00'),
(5, 1, 'Cannot access shared drive Finance', 'Access', 'High', 'resolved', 'I lost access to \\shared\finance folder after the password change. Error: Access Denied.', '2026-01-12 09:20:00', '2026-01-13 16:00:00'),
(6, 1, 'Printer not working - floor 2', 'Hardware', 'Medium', 'open', 'HP LaserJet on floor 2 shows paper jam error even though there is no jam. Tried power cycle twice.', '2026-01-15 14:10:00', '2026-01-15 14:10:00'),
(7, 1, 'Password reset for HR portal', 'Access', 'Medium', 'closed', 'I am locked out of the HR self-service portal after 3 wrong attempts. Please reset.', '2026-01-18 10:05:00', '2026-01-18 11:00:00'),
(8, 1, 'Software install: PDF reader', 'Software', 'Low', 'resolved', 'Need an approved PDF reader installed for audit documents. Laptop asset: LT-2041.', '2026-01-20 09:00:00', '2026-01-21 09:00:00'),
(9, 1, 'Wi-Fi weak in meeting room B', 'Network', 'Medium', 'in_progress', 'Video calls drop in meeting room B. Signal shows 1 bar. Can the AP be checked?', '2026-02-01 15:30:00', '2026-02-02 10:00:00'),
(10, 1, 'Blue screen on startup', 'Hardware', 'High', 'open', 'Getting BSOD with code 0x0000007E on startup twice this week. Happens before login screen.', '2026-02-03 08:00:00', '2026-02-03 08:00:00'),
(11, 1, 'Expense report approval stuck', 'Software', 'Medium', 'resolved', 'My January expense report is stuck at manager approval step for 5 days. Workflow ID EXP-2026-011.', '2026-02-05 12:00:00', '2026-02-06 09:00:00'),
(12, 1, 'New joiner account setup', 'Access', 'Medium', 'closed', 'New accountant joins Sunday. Please prepare email + ERP access. Details in HR ticket HR-88.', '2026-02-08 10:00:00', '2026-02-09 10:00:00'),
(13, 1, 'Antivirus blocking payroll app', 'Software', 'Low', 'closed', 'Endpoint protection quarantines payroll.exe as suspicious. Hash verified with vendor. Please allowlist.', '2026-02-10 11:00:00', '2026-02-11 11:00:00'),
(14, 1, 'Scanner not detected - finance', 'Hardware', 'Medium', 'open', 'Canon scanner in finance room is not detected by Document Scan app since Tuesday. USB cable checked, power on. Asset SC-011.', '2026-02-12 09:30:00', '2026-02-12 09:30:00'),
(15, 1, 'Q3 financial report export fails - error 0x8004', 'Software', 'Urgent', 'in_progress', 'When exporting the Q3 consolidated financial report from ERP as PDF, it fails with error 0x8004 after 2 minutes. This is needed urgently for the external audit next week. File size ~180MB. Tried Chrome and Edge.', '2026-02-13 10:15:00', '2026-02-13 10:15:00');

INSERT OR IGNORE INTO replies (id, ticket_id, user_id, body, is_staff, created_at) VALUES
(1, 1, 2, 'Hi Layla, we re-created your Outlook profile. Please restart Outlook and confirm sync works.', 1, '2026-01-07 14:00:00'),
(2, 3, 2, 'Hello, please update VPN client to v5.2 and try switching to TCP mode. Let us know if drops continue.', 1, '2026-01-10 12:00:00'),
(3, 6, 2, 'We have assigned a technician to check the floor 2 printer tomorrow morning.', 1, '2026-01-15 16:00:00'),
(4, 14, 2, 'Hi Layla, we ordered a replacement USB cable and will test the scanner driver v3.1 on Sunday.', 1, '2026-02-12 14:00:00');
