/* CTI Casefile — Scenario definition
 * Pure data. Loaded as a classic script so the app also works from file://
 * (fetch() of JSON would be blocked by CORS on a local disk).
 *
 * Source of truth for content: ../new.scenario (beginner-explicit-credentials-001)
 *
 * Note on answer order: the engine re-orders every question from the case seed
 * (see shuffleCase in app.js), so the order below is only the authoring order.
 * It is deliberately varied anyway — no single-answer question puts the correct
 * option first, and no multi-select question puts the correct options in the
 * leading slots — so the source is safe to read even without the shuffle.
 */
(function () {
  window.CTI_SCENARIOS = window.CTI_SCENARIOS || [];

  window.CTI_SCENARIOS.push({
    id: 'beginner-explicit-credentials-001',
    title: 'The Three Names',
    difficulty: 'Beginner',
    seed: 112,
    caseRef: 'CASE 009',
    host: 'sec-win-01',
    host_ip: '10.0.4.10',
    log_sources: ['auth'],

    mission: {
      brief: 'Investigate workstation sec-win-01.',
      objective: 'Establish who used three privileged credentials on this host in three minutes, and how.',
      client: 'Internal Security Operations — Tier 1 Escalation Desk'
    },

    narrative:
      'An attacker who was already logged in as an ordinary user injected explicit credentials for three ' +
      "different privileged accounts in rapid succession on the same host, then authenticated as " +
      'Administrator. Explicit credential use \u2014 Event 4648 \u2014 is how Windows records a process ' +
      "launched with credentials other than the logged-in user's, and stacking three of them on one " +
      'workstation is a strong lateral/privilege signal.',

    /* ---------------------------------------------------------------
     * Strings the engine reads from the scenario, so no fact about this
     * case is written into app.js. Every value here comes from new.scenario;
     * the evidence, stream and questions that follow are built on it.
     * --------------------------------------------------------------- */
    engine: {
      /* stage 2 — the record stream banner */
      stream: {
        window: '08:00–08:45',
        files: ['secwin1-events.evtx']
      },

      /* stage 5 / 6 — section headings and the progress checklist labels */
      sections: {
        behaviour: 'name the behaviour',
        second: 'read the credential trail',
        trail: 'assemble the sequence',
        attack: 'map it to attack',
        attackAlso: 'supporting techniques',
        iocs: 'keep the intelligence'
      },

      /* stage 1 — the three questions the analyst carries into the data */
      carryQuestions: [
        'Who was logged on when these events fired, and who was not?',
        'What is Event 4648 actually recording — a logon, or something that happens before one?',
        'Why three different accounts in three minutes, and which of them was then used?'
      ],

      /* stage 3 — what the cadence of the sequence means */
      cadenceNote:
        'The cadence is the finding: three explicit-credential events in two minutes and forty seconds, then a ' +
        'successful logon for Administrator ninety seconds after the last of them, then a command shell inside ' +
        'the Administrator session. This is somebody shopping for a credential that works \u2014 and the one they ' +
        'settled on is named in the fourth record.',

      /* ledger wording, so the analyst journal reads in the case's own terms */
      awards: {
        evidence:
          'Reviewed the full evidence set: three alerts plus account and privilege reference data',
        timeline:
          'Identified the pattern: three privileged credentials stacked on one host, then one of them used',
        triageContext:
          'Kept the ordinary logon as context rather than evidence — it names the session, not the misuse',
        board:
          'Correlated the full chain: svega session → three explicit credentials → Administrator accepted → ' +
          'command shell',
        attack: 'Mapped the outcome to ATT&CK T1078 Valid Accounts',
        attackAlso:
          'Identified the supporting technique: T1059.003 Windows Command Shell — and separated Event 4648 from ' +
          'Event 4624, which is the distinction this case is built on',
        host: 'Scoped the incident to host sec-win-01'
      },

      /* stage 5 — the collapsed trail card, and its journal entry */
      trailRows: [
        { k: 'Session', v: 'svega', flag: '— ordinary domain user, no administrative rights' },
        { k: 'Explicit', v: 'Administrator, svc_sql, svc_backup', flag: '— 4648 is a launch, not a logon' },
        { k: 'Accepted', v: 'Administrator 4624', flag: '— the only credential that was actually used' },
        { k: 'Trail', v: 'svega 08:01:05 → 4648 ×3 08:04:12–08:05:44 → 4624 Administrator 08:06:31 → cmd.exe 08:08:19' }
      ],
      trailLabel: 'REVEAL THE FULL CREDENTIAL TRAIL',
      journalDecode:
        'Assembled the credential trail — session as svega at 08:01:05, three explicit-credential events between ' +
        '08:04:12 and 08:05:44, Administrator logged on at 08:06:31, cmd.exe at 08:08:19',

      /* stage 6 — the live assessment preview */
      reportPreview: {
        rows: [
          { label: 'Host', value: 'sec-win-01 (10.0.4.10)', code: true },
          { label: 'Session', value: 'svega — ordinary domain user, no administrative rights', code: true },
          { label: 'Explicit credentials', value: 'Administrator, svc_sql, svc_backup — 3 × 4648 in 2m32s', code: true },
          { label: 'Used', value: 'Administrator — 1 × 4624, then cmd.exe inside that session', code: true },
          { label: 'Not logged on', value: 'svc_sql and svc_backup were never logged on on this host', code: false },
          { label: 'TTP', value: 'Valid Accounts T1078 — privilege escalation', code: false }
        ],
        note:
          'Assemble your justification in the fields above. The assessment is only defensible if the reasoning ' +
          'is visible.'
      }
    },

    /* ---------------------------------------------------------------
     * STAGE 2 — TRIAGE
     * The student tags each event as signal / context / noise.
     * tags: 'signal' | 'context' | 'noise'
     * --------------------------------------------------------------- */
    events: [
      {
        id: 'ev-4624-svega',
        ts: '08:01:05',
        code: 4624,
        kind: 'event',
        host: 'sec-win-01',
        actor: 'svega',
        text: 'Successful logon. Account "svega". Logon type 2 (interactive). Source 10.0.4.10.',
        tags: 'context',
        why:
          'An ordinary morning logon for an ordinary user. It is the frame the rest of the hour hangs on: every ' +
          'record that follows names this session as its subject, which is how three credentials end up ' +
          'attributed to a user who holds none of them.'
      },
      {
        id: 'ev-4648-administrator',
        ts: '08:04:12',
        code: 4648,
        kind: 'event',
        host: 'sec-win-01',
        actor: 'svega',
        text: 'Explicit credential use. Subject: svega. Credential: CORP\\Administrator. Target process: runas.exe. Target server: sec-win-01.',
        tags: 'signal',
        why:
          'Event 4648 is not a logon \u2014 it is a process being launched with credentials other than the ' +
          'logged-on user\u2019s. A standard user has no legitimate reason to launch anything as domain ' +
          'Administrator, and going through runas.exe to do it is a person at a keyboard.'
      },
      {
        id: 'ev-4648-svcsql',
        ts: '08:04:58',
        code: 4648,
        kind: 'event',
        host: 'sec-win-01',
        actor: 'svega',
        text: 'Explicit credential use. Subject: svega. Credential: CORP\\svc_sql. Target process: runas.exe. Target server: sec-win-01.',
        tags: 'signal',
        why:
          'Second in the sequence, 46 seconds after the first, and a different account. One explicit credential ' +
          'use can be a mis-click; three in under three minutes is somebody testing what they have \u2014 and ' +
          'svc_sql holds database rights, so this is not a step towards the same goal as Administrator.'
      },
      {
        id: 'ev-4648-svcbackup',
        ts: '08:05:44',
        code: 4648,
        kind: 'event',
        host: 'sec-win-01',
        actor: 'svega',
        text: 'Explicit credential use. Subject: svega. Credential: CORP\\svc_backup. Target process: runas.exe. Target server: sec-win-01.',
        tags: 'signal',
        why:
          'Third, and the pattern is now established: three different privileged identities, one host, one ' +
          'unprivileged session, 2 minutes 32 seconds. What the analyst should notice is what has not happened ' +
          '\u2014 neither svc_sql nor svc_backup has actually logged on.'
      },
      {
        id: 'ev-4624-administrator',
        ts: '08:06:31',
        code: 4624,
        kind: 'event',
        host: 'sec-win-01',
        actor: 'Administrator',
        text: 'Successful logon. Account "Administrator". Logon type 2 (interactive). Source 10.0.4.10.',
        tags: 'signal',
        why:
          '47 seconds after the last explicit-credential event, the credential that was launched actually ' +
          'authenticated. This is the line between 4648 and 4624, and it is the only one of the three ' +
          'credentials that turned out to work \u2014 which is itself the finding: two of them were tried and ' +
          'abandoned.'
      },
      {
        id: 'ev-4688-cmd',
        ts: '08:08:19',
        code: 4688,
        kind: 'event',
        host: 'sec-win-01',
        actor: 'Administrator',
        text: 'Process created by Administrator: cmd.exe (Command Prompt). Parent: winlogon.exe.',
        tags: 'signal',
        why:
          'A command shell parented by winlogon means an interactive Administrator session now exists \u2014 the ' +
          'escalation is complete, not merely attempted. Two minutes after the successful logon, the person at ' +
          'the keyboard is working as the most privileged identity on the domain.'
      },

      /* ---------- noise: baseline user activity ---------- */
      { id: 'ev-n01', ts: '08:00:31', code: 4624, kind: 'event', host: 'FIN-WS-14', actor: 'jdoe', text: 'Successful logon. Logon type 2. Source 10.0.4.10.', tags: 'noise' },
      { id: 'ev-n02', ts: '08:02:05', code: 4634, kind: 'event', host: 'FIN-WS-14', actor: 'jdoe', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n03', ts: '08:02:52', code: 4672, kind: 'event', host: 'HR-LT-03', actor: 'asmith', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n04', ts: '08:03:44', code: 4624, kind: 'event', host: 'OPS-WS-09', actor: 'mchen', text: 'Successful logon. Logon type 2. Source 10.0.4.11.', tags: 'noise' },
      { id: 'ev-n05', ts: '08:05:11', code: 4634, kind: 'event', host: 'FIN-WS-14', actor: 'jdoe', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n06', ts: '08:05:37', code: 4624, kind: 'event', host: 'ENG-WS-02', actor: 'kpatel', text: 'Successful logon. Logon type 2. Source 10.0.4.20.', tags: 'noise' },
      { id: 'ev-n07', ts: '08:06:47', code: 4634, kind: 'event', host: 'HR-LT-03', actor: 'asmith', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n08', ts: '08:07:55', code: 4672, kind: 'event', host: 'OPS-WS-09', actor: 'mchen', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n09', ts: '08:08:12', code: 4624, kind: 'event', host: 'FIN-LT-11', actor: 'rneuman', text: 'Successful logon. Logon type 2. Source 10.0.4.21.', tags: 'noise' },
      { id: 'ev-n10', ts: '08:09:26', code: 4634, kind: 'event', host: 'OPS-WS-09', actor: 'mchen', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n11', ts: '08:10:41', code: 4672, kind: 'event', host: 'HR-LT-03', actor: 'svega', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n12', ts: '08:11:48', code: 4624, kind: 'event', host: 'ENG-WS-02', actor: 'svega', text: 'Successful logon. Logon type 2. Source 10.0.4.11.', tags: 'noise' },
      { id: 'ev-n13', ts: '08:12:55', code: 4634, kind: 'event', host: 'FIN-LT-11', actor: 'rneuman', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n14', ts: '08:14:22', code: 4624, kind: 'event', host: 'HR-LT-03', actor: 'svega', text: 'Successful logon. Logon type 2. Source 10.0.4.20.', tags: 'noise' },
      { id: 'ev-n15', ts: '08:16:34', code: 4634, kind: 'event', host: 'ENG-WS-02', actor: 'kpatel', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n16', ts: '08:17:08', code: 4672, kind: 'event', host: 'FIN-WS-14', actor: 'jdoe', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n17', ts: '08:19:24', code: 4624, kind: 'event', host: 'SALES-LT-11', actor: 'asmith', text: 'Successful logon. Logon type 2. Source 10.0.4.11.', tags: 'noise' },
      { id: 'ev-n18', ts: '08:21:41', code: 4634, kind: 'event', host: 'SALES-LT-11', actor: 'rneuman', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n19', ts: '08:24:06', code: 4624, kind: 'event', host: 'FIN-LT-11', actor: 'kpatel', text: 'Successful logon. Logon type 2. Source 10.0.4.10.', tags: 'noise' },
      { id: 'ev-n20', ts: '08:26:19', code: 4672, kind: 'event', host: 'HR-LT-03', actor: 'asmith', text: 'Special privileges assigned to new logon.', tags: 'noise' }
    ],

    /* ---------------------------------------------------------------
     * STAGE 1 — EVIDENCE INBOX
     * --------------------------------------------------------------- */
    evidence: [
      {
        id: 'al-4648-stack',
        ref: 'ALERT-01',
        severity: 'high',
        title: 'Multiple explicit credential uses on one host',
        blurb: "Three explicit-credential logon events (Event 4648) were recorded on sec-win-01 within 3 minutes, targeting accounts 'Administrator', 'svc_sql', and 'svc_backup'.",
        detail:
          'Security Event 4648 \u2014 "A subject was specified using credentials". It fires when a process is ' +
          'launched with credentials other than those of the logged-on user, typically through runas.exe. It is ' +
          'frequently described as "explicit credential logon", which is how it becomes invisible: no logon has ' +
          'occurred yet, so a review that counts 4624 events sees an ordinary morning. Three on one host inside ' +
          'three minutes is a credential search, not a task.',
        hint: 'Ask: what does 4648 record, and what has to happen next for it to matter?'
      },
      {
        id: 'al-4648-admin',
        ref: 'ALERT-02',
        severity: 'high',
        title: 'Explicit credentials for Administrator account',
        blurb: "Process launched on sec-win-01 with explicit credentials for the domain Administrator account. Only Tier-0 administrators should ever authenticate this way.",
        detail:
          'The first of the three events, at 08:04:12, subject svega, credential CORP\\Administrator, target ' +
          'runas.exe on the same host. The built-in Administrator account is the one identity on a Windows ' +
          'domain that is expected to authenticate interactively in almost no circumstances; it exists to be ' +
          'used by management agents, never by a person at a keyboard. The subject of the record \u2014 the ' +
          'account the process runs as \u2014 is what makes this one a finding.',
        hint: 'Ask: who ran the process, whose credentials did it carry, and should that combination ever happen?'
      },
      {
        id: 'al-4624-after',
        ref: 'ALERT-03',
        severity: 'high',
        title: 'Privileged logon after explicit credential stacking',
        blurb: 'The Administrator account successfully authenticated on sec-win-01 immediately after three explicit-credential events.',
        detail:
          'Event 4624 at 08:06:31 \u2014 47 seconds after the last 4648 \u2014 for Administrator, logon type 2, ' +
          'interactive, followed at 08:08:19 by cmd.exe parented by winlogon.exe inside that session. Read ' +
          'the two together and the escalation is complete; read only the 4624 and it looks like an ' +
          'administrator sitting down at a machine. Of the three credentials tried, only this one was used.',
        hint: 'Ask: how long between the attempt and the result, and what happened inside the session after?'
      },
      {
        id: 'ev-user',
        ref: 'EVID-04',
        severity: 'info',
        title: 'Account information — svega',
        blurb: 'Directory record for the account whose session carried the explicit credentials.',
        detail:
          'svega \u2014 S. Vega, Logistics Coordinator, 19 months in post. Group membership: Domain Users and ' +
          'Logistics-Read. Not a member of local Administrators, not in the SQL or Backup operators groups, and ' +
          'not entitled to run anything as another user. Explicit-credential use by this account in 180 days: ' +
          'none. Interactive logon history: 10.0.4.x only.',
        hint: 'Ask: is this account entitled to launch anything as another identity, ever?'
      },
      {
        id: 'ev-baseline',
        ref: 'EVID-05',
        severity: 'info',
        title: 'Baseline activity — other hosts this hour',
        blurb: 'Reference traffic and credential-use records for the estate during the same window.',
        detail:
          'Five baseline users generated 20 logon, logoff and privilege events across FIN-WS-14, HR-LT-03, ' +
          'ENG-WS-02, OPS-WS-09, FIN-LT-11 and SALES-LT-11 in this hour. Across 1,180 workstations, Event ' +
          '4648 fired seven times in the same window: six of them by the service accounts that hold them, all ' +
          'targeted at the host they run on. Nobody logged on as CORP\\Administrator anywhere in the estate ' +
          'today, and no standard user account has ever produced three 4648 events on one host in an hour.',
        hint: 'Ask: what does 4648 look like when it is routine, and does this host match that shape?'
      }
    ],

    alerts: [
      { name: 'Multiple explicit credential uses on one host', severity: 'high' },
      { name: 'Explicit credentials for Administrator account', severity: 'high' },
      { name: 'Privileged logon after explicit credential stacking', severity: 'high' }
    ],

    /* ---------------------------------------------------------------
     * STAGE 3 — TIMELINE
     * --------------------------------------------------------------- */
    timeline: [
      { t: 'T+0', ts: '08:01:05', label: 'Logon', detail: 'successful_logon (4624): svega interactive on sec-win-01 from 10.0.4.10', net: null },
      { t: 'T+3', ts: '08:04:12', label: 'Explicit', detail: "explicit_credential_use (4648) \u00d73: svega launches runas.exe as CORP\\Administrator (08:04:12), CORP\\svc_sql (08:04:58), CORP\\svc_backup (08:05:44)", net: null },
      { t: 'T+5', ts: '08:06:31', label: 'Logon', detail: 'successful_logon (4624): Administrator interactive on sec-win-01 from 10.0.4.10', net: null },
      { t: 'T+7', ts: '08:08:19', label: 'Process', detail: 'process_created (4688): cmd.exe spawned by Administrator, parent winlogon.exe', net: null }
    ],

    timelineQuestion: {
      id: 'q-timeline',
      prompt: 'What pattern do you see in this sequence?',
      options: [
        { id: 'a', label: 'A support engineer with a delegated account testing their own access before a ticket' },
        { id: 'b', label: 'A scheduled management agent using explicit credentials to install a routine patch' },
        { id: 'c', label: 'An administrator opening three tools in quick succession at the start of the working day' },
        { id: 'd', label: 'An unprivileged session trying several privileged identities, one of which finally authenticates and opens a shell' }
      ],
      correct: ['d'],
      xp: 10,
      explain:
        'The three records that are usually conflated have to be read apart: 4624 is a session, 4648 is a ' +
        'launch with someone else\u2019s credentials, and 4624 again is the credential finally working. The ' +
        'pattern is a search followed by a result \u2014 three attempts, one success, and a shell inside the ' +
        'successful session. A management agent uses the credential it holds rather than hunting through ' +
        'three, and a support engineer with delegated rights produces none of these records at all.'
    },

    /* ---------------------------------------------------------------
     * STAGE 4 — CORRELATION BOARD
     * --------------------------------------------------------------- */
    boardNodes: [
      { id: 'n-session', label: 'svega session', sub: 'ordinary user, no admin rights', x: 8, y: 8 },
      { id: 'n-stacker', label: '3 × Event 4648', sub: 'explicit credential use', x: 8, y: 62 },
      { id: 'n-admin', label: 'CORP\\Administrator', sub: 'first credential tried', x: 40, y: 36 },
      { id: 'n-sql', label: 'svc_sql', sub: 'tried, never logged on', x: 40, y: 82 },
      { id: 'n-accepted', label: '4624 Administrator', sub: 'the one that worked', x: 72, y: 8 },
      { id: 'n-shell', label: 'cmd.exe', sub: 'inside the admin session', x: 72, y: 62 }
    ],
    boardLinks: [
      { from: 'n-session', to: 'n-stacker', label: 'carries', correct: true },
      { from: 'n-stacker', to: 'n-admin', label: 'targets', correct: true },
      { from: 'n-stacker', to: 'n-sql', label: 'targets', correct: true },
      { from: 'n-admin', to: 'n-accepted', label: 'authenticates as', correct: true },
      { from: 'n-accepted', to: 'n-shell', label: 'spawns', correct: true },
      { from: 'n-sql', to: 'n-accepted', label: 'authenticates as', correct: false },
      { from: 'n-session', to: 'n-shell', label: 'launches', correct: false }
    ],
    boardXp: 10,

    /* ---------------------------------------------------------------
     * STAGE 5 — ANALYSIS: behaviour, ATT&CK, IoCs
     * --------------------------------------------------------------- */
    behaviourQuestions: [
      {
        id: 'q-persist',
        prompt: 'How would you classify an unprivileged session ending up with an interactive Administrator session?',
        options: [
          { id: 'a', label: 'Persistence \u2014 the Administrator session will still exist after the machine reboots' },
          { id: 'b', label: 'Privilege escalation \u2014 a standard user obtained rights it was never granted' },
          { id: 'c', label: 'Initial Access \u2014 this is how the session began' },
          { id: 'd', label: 'Credential Access \u2014 the passwords were read out of memory' }
        ],
        correct: ['b'],
        xp: 10,
        explain:
          'The session already existed; what changed is the rights attached to it. A standard user ' +
          'authenticating as domain Administrator is privilege escalation, and the escalation is complete ' +
          'rather than attempted once the 4624 and the shell inside it are both present. Nothing here is ' +
          'persistence (the session ends when it ends), nothing was dumped from memory, and the logon at ' +
          '08:01 was not the access \u2014 the 4624 for Administrator is.'
      },
      {
        id: 'q-ps',
        prompt: 'Why does it matter that two of the three credentials were tried and abandoned?',
        options: [
          { id: 'a', label: 'It does not \u2014 a failed attempt is not a finding' },
          { id: 'b', label: 'It shows the person did not know which credentials they had, which makes the whole activity opportunistic rather than targeted' },
          { id: 'c', label: 'It shows the two service accounts were deleted immediately afterwards' },
          { id: 'd', label: 'It shows Windows blocked the first two attempts for security reasons' }
        ],
        correct: ['b'],
        xp: 10,
        explain:
          'Nobody runs runas.exe three times with three different identities unless they are trying to find ' +
          'out what they hold. A targeted attacker with a specific objective names the account they want and ' +
          'uses it \u2014 which is exactly what happened at 08:06:31. So the two failures are not noise around ' +
          'the event: they are the evidence of a search, and they are also why the value of whatever was ' +
          'accessible to svc_sql is part of the scoping question.'
      }
    ],

    decodedCommand: {
      encoded: 'svega 08:01:05 \u2192 4648 Administrator 08:04:12 \u2192 4648 svc_sql 08:04:58 \u2192 4648 svc_backup 08:05:44 \u2192 4624 Administrator 08:06:31 \u2192 cmd.exe 08:08:19',
      decoded: 'unprivileged interactive session (4624) \u2192 three explicit-credential launches (4648) \u2192 Administrator authenticates (4624) \u2192 command shell inside that session (4688)',
      note:
        'The case turns on one distinction: Event 4648 records a process being launched with credentials that ' +
        'are not the logged-on user\u2019s, and it is often summarised as "explicit credential logon" \u2014 which ' +
        'is how it hides from anyone counting 4624s. Nothing was escalated at 08:04:12; it was escalated at ' +
        '08:06:31, and the 4648s are the search that led there.'
    },

    attack: {
      /* the engine renders primary.prompt and alsoPresent.prompt as the question text */
      primary: {
        prompt: 'Which technique best explains the escalation itself?',
        options: [
          { id: 'a', label: 'OS Credential Dumping', meta: 'T1003 \u00b7 Credential Access' },
          { id: 'b', label: 'Exploitation for Privilege Escalation', meta: 'T1068 \u00b7 Privilege Escalation' },
          { id: 'c', label: 'Valid Accounts', meta: 'T1078 \u00b7 Defense Evasion / Privilege Escalation / Persistence' },
          { id: 'd', label: 'Process Injection', meta: 'T1055 \u00b7 Privilege Escalation / Defense Evasion' }
        ],
        correct: ['c'],
        xp: 10,
        explain:
          'No exploit was used, nothing was injected and nothing was dumped from memory: a standard user ' +
          'authenticated with credentials they were already holding. That is Valid Accounts, T1078 \u2014 and ' +
          'with stolen service and administrator credentials it is very often the primary technique rather ' +
          'than a fallback. The sub-technique would be T1078.002, domain accounts.'
      },
      alsoPresent: {
        prompt: 'One further technique is genuinely present. Select it.',
        options: [
          { id: 'a', label: 'OS Credential Dumping: LSASS Memory', meta: 'T1003.001 \u00b7 Credential Access' },
          { id: 'b', label: 'Windows Command Shell', meta: 'T1059.003 \u00b7 Execution' },
          { id: 'c', label: 'Exploitation of Remote Services', meta: 'T1210 \u00b7 Initial Access' },
          { id: 'd', label: 'Input Capture: Keylogging', meta: 'T1056.001 \u00b7 Credential Access' }
        ],
        correct: ['b'],
        xp: 10,
        explain:
          'cmd.exe parented by winlogon.exe inside the Administrator session is the Windows Command Shell, ' +
          'T1059.003 \u2014 the work being done once the rights were gained. Option A is the misreading this ' +
          'case exists to prevent: Event 4648 is sometimes described as an "explicit credential logon", and ' +
          'that shorthand is how a case about using credentials you already hold turns into a case about ' +
          'stealing them out of memory. Nothing here shows extraction \u2014 no LSASS access, no dump, no ' +
          'process injection \u2014 and knowing the difference is what keeps the response aimed at the right ' +
          'place. Options C and D describe nothing that appears in the stream at all.'
      }
    },

    iocs: {
      prompt: 'Which of these would you preserve as indicators or investigative pivots?',
      options: [
        { id: 'i1', label: 'Event 4648 by a non-administrative account', role: 'indicator' },
        { id: 'i2', label: 'CORP\\Administrator', role: 'indicator' },
        { id: 'i3', label: 'sec-win-01', role: 'context' },
        { id: 'i4', label: 'svega', role: 'context' },
        { id: 'i5', label: 'Event 4648', role: 'context' },
        { id: 'i6', label: 'three privileged credentials tried on one host in under three minutes', role: 'behaviour' },
        { id: 'i7', label: 'a successful privileged logon seconds after an explicit-credential attempt', role: 'behaviour' },
        { id: 'i8', label: 'a command shell parented by winlogon inside a privileged session', role: 'behaviour' }
      ],
      correct: ['indicator', 'behaviour', 'context'],
      xp: 10,
      explain:
        'Two of these eight are things you act on today: the detection rule \u2014 any 4648 whose subject is not ' +
        'entitled to run as another identity \u2014 and the identity CORP\\Administrator, which should never be ' +
        'authenticating interactively and whose use here is the finding. The behaviours are the detections ' +
        'worth engineering: three privileged credentials tried on one host in under three minutes, a privileged ' +
        'logon seconds after an attempt, and a shell parented by winlogon in a privileged session. sec-win-01, ' +
        'svega and Event 4648 itself are context \u2014 the code is the medium, not the indicator, and a report ' +
        'that lists it as one has not read its own records.'
    },

    /* ---------------------------------------------------------------
     * STAGE 6 — REPORT
     * --------------------------------------------------------------- */
    report: {
      host: {
        prompt: 'Which host is affected?',
        options: [
          { id: 'a', label: 'FIN-LT-11' },
          { id: 'b', label: '10.0.4.11' },
          { id: 'c', label: 'OPS-WS-09' },
          { id: 'd', label: 'sec-win-01' }
        ],
        correct: ['d'],
        xp: 10,
        explain:
          'All six relevant records originate on sec-win-01 \u2014 the svega session, the three explicit-credential ' +
          'events, the Administrator logon and the shell. 10.0.4.11 is an address used elsewhere in the estate ' +
          'and names no host here.'
      },
      what: {
        prompt: 'What happened?',
        options: [
          { id: 'a', label: 'A support engineer with delegated rights tested three accounts from their own session before raising a ticket.' },
          { id: 'b', label: 'A scheduled management agent used its explicit credentials to install a routine patch.' },
          { id: 'c', label: 'An administrator opened three tools in quick succession at the start of the working day.' },
          { id: 'd', label: 'An ordinary user session on sec-win-01 launched three processes with explicit credentials \u2014 Administrator, svc_sql and svc_backup \u2014 within 2 minutes 32 seconds; 47 seconds after the last attempt the Administrator credential actually authenticated, and a command shell was opened inside that session.' }
        ],
        correct: ['d'],
        xp: 10,
        explain:
          'The assessment has to carry the mechanism (explicit credentials), the count (three), the window ' +
          '(2 minutes 32 seconds), the result (only Administrator authenticated) and the consequence (a ' +
          'shell inside that session). A statement that says only "an administrator logged on" describes ' +
          'record 4624 and nothing else \u2014 and this case exists because that is exactly what a 4624-only ' +
          'review would have reported.'
      },
      why: {
        prompt: 'Why is it suspicious? Select every reason that holds.',
        options: [
          { id: 'a', label: 'The account doing this, svega, holds no administrative rights and has produced no explicit-credential events in 180 days' },
          { id: 'b', label: 'Three different privileged identities were tried on one host in under three minutes' },
          { id: 'c', label: 'CORP\\Administrator authenticated interactively, which has not happened anywhere in the estate today' },
          { id: 'd', label: 'Support engineers do use runas.exe, and this is how delegated access is normally exercised' },
          { id: 'e', label: 'Two of the three credentials were abandoned, which is the signature of a search rather than a task' },
          { id: 'f', label: 'A command shell was opened inside the Administrator session 47 seconds after the credential worked' }
        ],
        correct: ['a', 'b', 'c', 'e', 'f'],
        xp: 10,
        explain:
          'Five of these six are anchored to a record or a fact you were given: an account outside its ' +
          'entitlement, a rate, an identity that should never authenticate interactively, two failures that ' +
          'change how the whole sequence reads, and a shell confirming the escalation completed. Only option ' +
          'D is an assumption \u2014 and delegated access does not work by guessing three privileged names from ' +
          'a standard session, which is precisely the behaviour the records show.'
      },
      confidence: {
        prompt: 'Analyst confidence in this assessment',
        options: [
          { id: 'a', label: 'Low' },
          { id: 'b', label: 'Medium' },
          { id: 'c', label: 'High' }
        ],
        correct: ['c'],
        xp: 10,
        explain:
          'The 4648 records, the account entitlement, the estate-wide baseline and the successful logon all ' +
          'agree, and they agree on the sequencing as well as the facts: attempts, then a result, then work ' +
          'inside the session. The one thing the records cannot tell you is where the credentials came from, ' +
          'and that gap affects the scoping, not the finding.'
      },
      actions: {
        prompt: 'Recommended next actions. Select the three that follow from this assessment.',
        options: [
          { id: 'a', label: 'Reset the Administrator, svc_sql and svc_backup credentials estate-wide and re-deploy the services that hold them' },
          { id: 'b', label: 'Terminate the Administrator session on sec-win-01, preserve the host, and capture what was done inside it' },
          { id: 'c', label: 'Hunt for any other workstation where an account has used explicit credentials for a more privileged identity, and alert on 4648 by non-privileged subjects' },
          { id: 'd', label: 'Rebuild sec-win-01 and every workstation in the logistics group' },
          { id: 'e', label: 'Disable the runas.exe binary on all endpoints to prevent future explicit credential use' },
          { id: 'f', label: 'Add svc_sql to the Administrators group so support staff stop needing to escalate' }
        ],
        correct: ['a', 'b', 'c'],
        xp: 10,
        explain:
          'Contain the session and preserve it before anything is rebuilt \u2014 the shell at 08:08:19 is the ' +
          'start of what was done with domain Administrator rights, and that evidence exists nowhere else. ' +
          'Treat the credentials as compromised and rotate all three, with the service re-deployment included ' +
          'so nothing breaks. And hunt the pattern: 4648 by a subject not entitled to run as another identity ' +
          'is a rule you can deploy across the estate today. Options D and F are wrong in opposite directions, ' +
          'and E removes a tool that administrators legitimately use.'
      }
    },

    reasoning: {
      prompt: 'Which three pieces of evidence most strongly support your assessment? Select exactly three.',
      options: [
        { id: 'r1', label: 'svega is a member of Logistics-Read only', key: false },
        { id: 'r2', label: 'Three Event 4648 records on one host between 08:04:12 and 08:05:44, subject svega, credentials Administrator, svc_sql and svc_backup', key: true },
        { id: 'r3', label: 'Four other users were active on the estate during the same hour', key: false },
        { id: 'r4', label: 'svega holds no administrative rights and has produced no explicit-credential events in 180 days', key: true },
        { id: 'r5', label: 'Event 4672 appears on this host several times a day', key: false },
        { id: 'r6', label: 'Event 4624 for Administrator 47 seconds after the last attempt, then cmd.exe parented by winlogon.exe inside that session at 08:08:19', key: true },
        { id: 'r7', label: 'The workstation has the standard corporate build', key: false }
      ],
      correctCount: 3,
      xp: 10,
      explain:
        'The three that matter describe one escalation: a subject with no entitlement using explicit ' +
        'credentials three times in a row, and then that credential working. Between them they cover the ' +
        'mechanism, the entitlement and the result, which is the minimum a finding like this needs to survive ' +
        'challenge. Group membership on its own, estate busyness, routine privilege events and the software ' +
        'build are background \u2014 true, but they would not change a conclusion if they were removed.'
    },

    /* mirrored verbatim from new.scenario — the dotted keys are kept as written
       there, because this block is the record of what the case is actually made of */
    ground_truth: {
      explicit_credential_use_events: 3,
      distinct_accounts_used_with_explicit_creds: 3,
      successful_logons_for_administrator: 1,
      target_host: 'sec-win-01',
      event_ids_present: [4624, 4648, 4688]
    },

    ranking: [
      { min: 90, rank: 'Lead Intelligence Analyst', note: 'You produced defensible intelligence, not just correct answers.' },
      { min: 75, rank: 'Threat Intelligence Analyst', note: 'Strong correlation and a defensible judgment.' },
      { min: 55, rank: 'Junior CTI Investigator', note: 'You found the escalation and explained it. Tighten the correlation and the reporting.' },
      { min: 0, rank: 'Case Officer Trainee', note: 'Re-run the case. Start at Event 4648 and work out what it is not saying.' }
    ],

    assist: {
      nudge: { label: 'Nudge', mult: 0.85, text: 'Two of the three event codes on this host look alike and mean opposite things. Find out which is which.' },
      hint: { label: 'Analyst Hint', mult: 0.7, text: 'One code records a session starting. One records a process being launched with someone else\u2019s credentials. Only one of them is a logon.' },
      explain: { label: 'Explain', mult: 0.5, text: 'svega \u2014 who holds no administrative rights \u2014 logged on to sec-win-01 at 08:01:05. Between 08:04:12 and 08:05:44 three Event 4648 records fired on that host: processes launched with explicit credentials for CORP\\Administrator, svc_sql and svc_backup. Event 4648 is a launch with credentials other than the subject\u2019s, not a logon, which is why a review counting 4624s misses it entirely. At 08:06:31, 47 seconds after the last attempt, Administrator actually authenticated (4624), and at 08:08:19 cmd.exe was opened inside that session. The outcome is Valid Accounts, T1078, with the Windows Command Shell (T1059.003) as the work performed once rights were gained \u2014 not credential dumping, which is the misreading this case is built to prevent. Terminate the session, preserve the host, rotate all three credentials and alert on 4648 by non-privileged subjects.' }
    }
  });
})();