<script lang="ts">
  import {
    ApiError,
    getRejected,
    getStorageEstimate,
    getSettings,
    getStorageHistory,
    isConflict,
    putSettings,
    type RejectedSender,
    type Settings,
    type StorageHistoryEntry,
  } from '../lib/api';
  import { ago, approxDays, bytes, dateTime, GiB, MiB, num } from '../lib/format';
  import { deviceName, live, refreshStatus } from '../lib/status.svelte';
  import { auth, loadSession } from '../lib/session.svelte';
  import { router } from '../lib/router.svelte';
  import { failingNow, noteSave, undo, undoLastSave } from '../lib/undo.svelte';
  import PasswordForm from '../components/PasswordForm.svelte';
  import CopyButton from '../components/CopyButton.svelte';
  import TlsPanel from '../components/TlsPanel.svelte';
  import SnmpPanel from '../components/SnmpPanel.svelte';
  import { isCommunityHash } from '../lib/traps';
  import UpdatesSettings from '../components/UpdatesSettings.svelte';
  import PollStatePanel from '../components/PollStatePanel.svelte';
  import { PRESETS as POLL_PRESETS, pollSettingsBody, pollSettingsForm, type PollSettingsForm } from '../lib/poll';
  import FlowStatePanel from '../components/FlowStatePanel.svelte';
  import { budgetOf, flowBudgetBody, flowFormErrors, flowListenerBody, flowSettingsForm, ruleIesOf, type FlowSettingsForm } from '../lib/flows';

  // The form edits friendlier units (GiB, MiB, minutes, one CIDR per line) and converts on save.
  interface Form extends PollSettingsForm, FlowSettingsForm {
    udpEnabled: boolean;
    udpAddr: string;
    udpPort: number;
    tcpEnabled: boolean;
    tcpAddr: string;
    tcpPort: number;
    tlsEnabled: boolean;
    tlsAddr: string;
    tlsPort: number;
    tlsLegacy: boolean;
    /** Woodshed's own CA, or the user's certificate and key files. */
    tlsSource: 'woodshed' | 'file';
    tlsCertFile: string;
    tlsKeyFile: string;
    snmpEnabled: boolean;
    snmpAddr: string;
    snmpPort: number;
    snmpInforms: boolean;
    /** "#<hash8>" for a stored community (sent back to keep it), the text of one added since the last save. */
    snmpCommunities: string[];
    snmpMibDir: string;
    snmpEngineId: string;
    allowlist: string;
    blocklist: string;
    maxDevices: number;
    burst: number;
    perMinute: number;
    dataDir: string;
    retentionDays: number;
    retentionGiB: number;
    partMiB: number;
    lanMode: boolean;
    requireLocal: boolean;
    uiPort: number;
    certFile: string;
    keyFile: string;
    extraHostnames: string;
    trustedHosts: string;
    quietMin: number;
    offlineMin: number;
  }

  let saved = $state<Settings | null>(null);
  /** The ETag `saved` was read or saved at; sent as If-Match on save. */
  let etag = '';
  let form = $state<Form | null>(null);
  let loadError = $state('');
  let errors = $state<Record<string, string>>({});
  let formError = $state('');
  let busy = $state(false);
  let savedAt = $state(0);
  /** Bumped on every save, so the TLS panel reads the certificate again (the first turn-on creates it). */
  let saves = $state(0);
  /** Set after a save that changed lan_mode or the UI port: the server restarts at a new address. */
  let moved = $state<{ url: string; lan: boolean; port: number } | null>(null);
  let history = $state<StorageHistoryEntry[] | null>(null);
  let rejected = $state<RejectedSender[] | null>(null);
  /**
   * A save refused with 409: the settings changed elsewhere (another tab, a script, Block on
   * a device). The user's edits stay listed after Reload so they can redo them.
   */
  let conflict = $state<{ edits: { key: keyof Form; label: string; mine: string }[]; reloaded: boolean } | null>(null);
  let reloading = $state(false);
  /** The lists as last sent, so "listeners.allowlist[2]" errors can name the entry. */
  let sentLists = $state<Record<string, string[]>>({});

  const round = (n: number, d = 2) => Math.round(n * 10 ** d) / 10 ** d;

  /** A community being typed; it's added to the draft list and sent on Save, then shown only as its hash. */
  let newCommunity = $state('');
  function addCommunity() {
    const c = newCommunity;
    if (!form || !c) return;
    if (!form.snmpCommunities.includes(c)) form.snmpCommunities = [...form.snmpCommunities, c];
    newCommunity = '';
  }

  function toForm(s: Settings): Form {
    return {
      udpEnabled: s.listeners.udp.enabled,
      udpAddr: s.listeners.udp.addr,
      udpPort: s.listeners.udp.port,
      tcpEnabled: s.listeners.tcp.enabled,
      tcpAddr: s.listeners.tcp.addr,
      tcpPort: s.listeners.tcp.port,
      tlsEnabled: !!s.listeners.tls?.enabled,
      tlsAddr: s.listeners.tls?.addr ?? '0.0.0.0',
      tlsPort: s.listeners.tls?.port ?? 6514,
      tlsLegacy: !!s.listeners.tls?.allow_legacy_tls,
      tlsSource: s.listeners.tls?.cert_file || s.listeners.tls?.key_file ? 'file' : 'woodshed',
      tlsCertFile: s.listeners.tls?.cert_file ?? '',
      tlsKeyFile: s.listeners.tls?.key_file ?? '',
      snmpEnabled: !!s.listeners.snmp?.enabled,
      snmpAddr: s.listeners.snmp?.addr ?? '0.0.0.0',
      snmpPort: s.listeners.snmp?.port ?? 162,
      snmpInforms: s.listeners.snmp?.answer_informs ?? true,
      snmpCommunities: [...(s.listeners.snmp?.communities ?? [])],
      snmpMibDir: s.listeners.snmp?.mib_dir ?? '',
      snmpEngineId: s.listeners.snmp?.engine_id ?? '',
      allowlist: s.listeners.allowlist.join('\n'),
      blocklist: (s.listeners.blocklist ?? []).join('\n'),
      maxDevices: s.listeners.max_devices,
      burst: s.listeners.new_device_burst,
      perMinute: s.listeners.new_devices_per_minute,
      dataDir: s.storage.data_dir,
      retentionDays: s.storage.retention_days,
      retentionGiB: round(s.storage.retention_bytes / GiB),
      partMiB: round(s.storage.part_bytes / MiB),
      lanMode: s.ui.lan_mode,
      requireLocal: !!s.ui.require_login_local,
      uiPort: s.ui.port,
      certFile: s.ui.cert_file ?? '',
      keyFile: s.ui.key_file ?? '',
      extraHostnames: (s.ui.extra_hostnames ?? []).join('\n'),
      trustedHosts: (s.ui.trusted_hosts ?? []).join('\n'),
      quietMin: round(s.quiet.quiet_after_seconds / 60),
      offlineMin: round(s.quiet.offline_after_seconds / 60),
      ...pollSettingsForm(s.poll),
      ...flowSettingsForm(s.listeners.flow, s.storage.flow_budget_bytes),
    };
  }

  // Empty number inputs bind to null; send NaN-free values and let the server reject them.
  const n = (v: number | null) => (typeof v === 'number' && Number.isFinite(v) ? v : 0);

  function fromForm(f: Form): Settings {
    return {
      listeners: {
        udp: { enabled: f.udpEnabled, addr: f.udpAddr.trim(), port: n(f.udpPort) },
        tcp: { enabled: f.tcpEnabled, addr: f.tcpAddr.trim(), port: n(f.tcpPort) },
        // Sent only to a server that has the TLS listener (1.1 and later).
        ...(saved?.listeners.tls
          ? {
              tls: {
                enabled: f.tlsEnabled,
                addr: f.tlsAddr.trim(),
                port: n(f.tlsPort),
                allow_legacy_tls: f.tlsLegacy,
                cert_file: f.tlsSource === 'file' ? f.tlsCertFile.trim() : '',
                key_file: f.tlsSource === 'file' ? f.tlsKeyFile.trim() : '',
              },
            }
          : {}),
        // Sent only to a server that has the SNMP trap listener (1.2 and later).
        ...(saved?.listeners.snmp
          ? {
              snmp: {
                enabled: f.snmpEnabled,
                addr: f.snmpAddr.trim(),
                port: n(f.snmpPort),
                answer_informs: f.snmpInforms,
                communities: [...f.snmpCommunities],
                mib_dir: f.snmpMibDir.trim(),
                engine_id: f.snmpEngineId.trim(),
              },
            }
          : {}),
        // Sent only to a server that has flows (2.0 and later).
        ...(saved?.listeners.flow ? { flow: flowListenerBody(f) } : {}),
        allowlist: parseAllowlist(f.allowlist),
        blocklist: parseAllowlist(f.blocklist),
        max_devices: n(f.maxDevices),
        new_device_burst: n(f.burst),
        new_devices_per_minute: n(f.perMinute),
      },
      storage: {
        data_dir: f.dataDir,
        retention_days: n(f.retentionDays),
        retention_bytes: Math.round(n(f.retentionGiB) * GiB),
        part_bytes: Math.round(n(f.partMiB) * MiB),
        ...(saved?.storage.flow_budget_bytes !== undefined ? { flow_budget_bytes: flowBudgetBody(f) } : {}),
      },
      ui: {
        lan_mode: f.lanMode,
        port: n(f.uiPort),
        cert_file: f.certFile.trim(),
        key_file: f.keyFile.trim(),
        require_login_local: f.requireLocal,
        extra_hostnames: parseAllowlist(f.extraHostnames),
        trusted_hosts: parseAllowlist(f.trustedHosts),
      },
      quiet: {
        quiet_after_seconds: Math.round(n(f.quietMin) * 60),
        offline_after_seconds: Math.round(n(f.offlineMin) * 60),
      },
      // Sent only to a server that has the poller (1.3 and later).
      ...(saved?.poll ? { poll: pollSettingsBody(f) } : {}),
    };
  }

  function parseAllowlist(text: string): string[] {
    return text
      .split(/[\s,]+/)
      .map((x) => x.trim())
      .filter(Boolean);
  }

  async function loadRejected() {
    try {
      rejected = await getRejected();
    } catch {
      rejected = rejected ?? [];
    }
  }

  $effect(() => {
    loadRejected();
    const t = setInterval(loadRejected, 15000);
    return () => clearInterval(t);
  });

  const hostCidr = (ip: string) => `${ip}/${ip.includes(':') ? 128 : 32}`;
  const inDraft = (ip: string) => !!form && parseAllowlist(form.allowlist).some((c) => c === ip || c === hostCidr(ip));

  function allow(ip: string) {
    if (!form || inDraft(ip)) return;
    const cur = form.allowlist.replace(/\s+$/, '');
    // docs/api.md: allowlist entries may be a bare IP or a CIDR.
    form.allowlist = cur ? `${cur}\n${ip}` : ip;
  }

  async function load() {
    try {
      const v = await getSettings();
      saved = v.settings;
      etag = v.etag;
      form = toForm(saved);
      loadError = '';
    } catch (e) {
      loadError = (e as Error).message;
    }
    try {
      history = await getStorageHistory();
    } catch {
      history = [];
    }
  }
  load();

  // The Updates switch saves on its own, which changes the settings' ETag. Take the new one
  // when nothing else changed, so the next Save isn't refused as a conflict.
  async function adoptEtag() {
    try {
      const v = await getSettings();
      if (saved && JSON.stringify(fromForm(toForm(v.settings))) === JSON.stringify(fromForm(toForm(saved)))) {
        saved = v.settings;
        etag = v.etag;
      }
    } catch {
      /* the next save reports it */
    }
  }

  // "Undo last save" (here or on the banner) put the old settings back: show them.
  let undoSeen = undo.version;
  $effect(() => {
    if (undo.version !== undoSeen) {
      undoSeen = undo.version;
      load();
    }
  });

  // The retention estimate for the cap being typed (docs/api.md), debounced.
  let est = $state<Awaited<ReturnType<typeof getStorageEstimate>> | null | undefined>(undefined);
  $effect(() => {
    const gib = form ? n(form.retentionGiB) : 0;
    if (!form || !(gib > 0)) return;
    const ctrl = new AbortController();
    const t = setTimeout(async () => {
      try {
        est = await getStorageEstimate(gib * GiB, ctrl.signal);
      } catch (e) {
        if ((e as Error).name !== 'AbortError') est = null;
      }
    }, 300);
    return () => {
      clearTimeout(t);
      ctrl.abort();
    };
  });

  // Banners and toasts link to a section: #/settings?section=limits, blocklist, storage, updates,
  // tls or tls-failures. Each new link scrolls once, also when this page is already open.
  let scrolledFor = '';
  $effect(() => {
    const m = /section=(limits|blocklist|storage|updates|tls-failures|tls|snmp-users|snmp-mibs|snmp-failures|snmp|polling|flows)\b/.exec(router.query);
    if (!form || !m || scrolledFor === router.query) return;
    scrolledFor = router.query;
    const id = m[1] === 'limits' ? 'sender-limits' : m[1];
    const to = () => document.getElementById(id)?.scrollIntoView({ block: 'start', behavior: 'instant' });
    requestAnimationFrame(to);
    // Lists above the section (refused senders, storage history) arrive a moment later and push
    // it down: land on it again unless the user has scrolled since.
    const y = { at: -1 };
    requestAnimationFrame(() => (y.at = scrollY));
    setTimeout(() => {
      if (scrollY === y.at) to();
    }, 700);
  });

  // Compared through the form, so key order and lists an older server omits don't count as edits.
  const savedForm = $derived(saved ? toForm(saved) : null);
  const savedJSON = $derived(savedForm ? JSON.stringify(fromForm(savedForm)) : '');
  const dirty = $derived(!!form && !!saved && JSON.stringify(fromForm(form)) !== savedJSON);

  // For the conflict notice: each edited field by its label, with the user's value.
  const LABELS: Record<keyof Form, string> = {
    udpEnabled: 'UDP listener',
    udpAddr: 'UDP bind address',
    udpPort: 'UDP port',
    tcpEnabled: 'TCP listener',
    tcpAddr: 'TCP bind address',
    tcpPort: 'TCP port',
    tlsEnabled: 'Syslog over TLS',
    tlsAddr: 'TLS bind address',
    tlsPort: 'TLS port',
    tlsLegacy: 'Allow TLS 1.0 and 1.1',
    tlsSource: 'TLS certificate',
    tlsCertFile: 'TLS certificate file',
    tlsKeyFile: 'TLS private key file',
    snmpEnabled: 'SNMP traps',
    snmpAddr: 'SNMP bind address',
    snmpPort: 'SNMP port',
    snmpInforms: 'Answer informs',
    snmpCommunities: 'Communities',
    snmpMibDir: 'MIB folder',
    snmpEngineId: 'Engine ID',
    allowlist: 'Sender allowlist',
    blocklist: 'Blocklist',
    maxDevices: 'Active devices',
    burst: 'New senders at once',
    perMinute: 'New senders per minute',
    dataDir: 'Data folder',
    retentionDays: 'Keep logs for (days)',
    retentionGiB: 'Disk cap (GiB)',
    partMiB: 'Split files at (MiB)',
    lanMode: 'LAN mode',
    requireLocal: 'Require login on this machine too',
    uiPort: 'UI port',
    certFile: 'Certificate file',
    keyFile: 'Private key file',
    extraHostnames: 'Extra certificate names',
    trustedHosts: 'Trusted host names',
    quietMin: 'Quiet after (minutes)',
    offlineMin: 'Offline after (minutes)',
    pollInterval: 'Poll every (seconds)',
    pollTimeoutMs: 'Poll timeout (ms)',
    pollRetries: 'Poll retries',
    pollConcurrency: 'Devices polled at once',
    pollMaxIf: 'Interfaces per device',
    pollMaxTargets: 'Most polled devices',
    pollPresets: 'Default presets',
    flowEnabled: 'Flows',
    flowAddr: 'Flow bind address',
    flowNetflowPort: 'NetFlow port',
    flowIpfixPort: 'IPFIX port',
    flowTimeout: 'Template timeout',
    flowRuleIes: 'Rule ID fields',
    flowBudgetGiB: 'Flow budget (GiB)',
  };
  const shown = (v: unknown): string => {
    if (typeof v === 'boolean') return v ? 'on' : 'off';
    const t = parseAllowlist(String(v ?? '')).join(', ');
    return t || '(empty)';
  };
  /** Communities are secrets: a new one is never shown again, here or in the conflict notice. */
  const shownField = (k: keyof Form, v: unknown) =>
    k === 'snmpCommunities' ? shown((v as string[]).map((c) => (isCommunityHash(c) ? c : '(new, hidden)')).join(' ')) : shown(v);
  function edits(from: Form, to: Form) {
    return (Object.keys(LABELS) as (keyof Form)[])
      .filter((k) => shownField(k, from[k]) !== shownField(k, to[k]))
      .map((k) => ({ key: k, label: LABELS[k], mine: shownField(k, to[k]) }));
  }

  async function reloadAfterConflict() {
    reloading = true;
    try {
      const v = await getSettings();
      saved = v.settings;
      etag = v.etag;
      form = toForm(saved);
      errors = {};
      formError = '';
      if (conflict) conflict = { ...conflict, reloaded: true };
    } catch (e) {
      formError = `Couldn't reload the settings: ${(e as Error).message}`;
    } finally {
      reloading = false;
    }
  }

  // The draft adds a certificate name: saving regenerates the self-signed certificate.
  const addsCertName = $derived(
    !!form && !!saved && parseAllowlist(form.extraHostnames).some((h) => !(saved?.ui.extra_hostnames ?? []).includes(h)),
  );

  // Field paths this page shows inline. Anything else the server reports goes in the summary.
  const FIELDS = [
    'listeners.udp.enabled',
    'listeners.udp.addr',
    'listeners.udp.port',
    'listeners.tcp.enabled',
    'listeners.tcp.addr',
    'listeners.tcp.port',
    'listeners.tls.enabled',
    'listeners.tls.addr',
    'listeners.tls.port',
    'listeners.tls.allow_legacy_tls',
    'listeners.tls.cert_file',
    'listeners.tls.key_file',
    'listeners.snmp.enabled',
    'listeners.snmp.addr',
    'listeners.snmp.port',
    'listeners.snmp.answer_informs',
    'listeners.snmp.communities',
    'listeners.snmp.mib_dir',
    'listeners.snmp.engine_id',
    'listeners.allowlist',
    'listeners.blocklist',
    'listeners.max_devices',
    'listeners.new_device_burst',
    'listeners.new_devices_per_minute',
    'storage.data_dir',
    'storage.retention_days',
    'storage.retention_bytes',
    'storage.part_bytes',
    'ui.lan_mode',
    'ui.require_login_local',
    'ui.port',
    'ui.cert_file',
    'ui.key_file',
    'ui.extra_hostnames',
    'ui.trusted_hosts',
    'quiet.quiet_after_seconds',
    'quiet.offline_after_seconds',
    'poll.interval_s',
    'poll.timeout_ms',
    'poll.retries',
    'poll.concurrency',
    'poll.max_interfaces',
    'poll.max_targets',
    'poll.presets',
    'listeners.flow.enabled',
    'listeners.flow.addr',
    'listeners.flow.netflow_port',
    'listeners.flow.ipfix_port',
    'listeners.flow.template_timeout',
    'listeners.flow.rule_id_ies',
    'storage.flow_budget_bytes',
  ];

  /**
   * The message(s) for a field. Error keys are dotted paths with [i] for list items
   * (docs/api.md), so "listeners.allowlist[2]" belongs to the allowlist field and is
   * shown as "Entry 3 (value): message".
   */
  function err(path: string): string {
    const out: string[] = [];
    if (errors[path]) out.push(errors[path]);
    for (const k of Object.keys(errors)) {
      const m = k.startsWith(`${path}[`) ? /^\[(\d+)\]$/.exec(k.slice(path.length)) : null;
      if (m) {
        const i = Number(m[1]);
        const v = sentLists[path]?.[i];
        out.push(`Entry ${i + 1}${v ? ` (${v})` : ''}: ${errors[k]}`);
      } else if (k.startsWith(`${path}.`) || (k.startsWith(`${path}[`) && k !== path)) {
        out.push(errors[k]);
      }
    }
    return out.join('\n');
  }
  const owned = (k: string) => FIELDS.some((f) => k === f || k.startsWith(`${f}.`) || k.startsWith(`${f}[`));
  const otherErrors = $derived(Object.entries(errors).filter(([k]) => !owned(k)));

  async function save(e: SubmitEvent) {
    e.preventDefault();
    if (!form) return;
    busy = true;
    errors = {};
    formError = '';
    const body = fromForm(form);
    // The flow form's own checks first, so a typo in a rule ID field is named before anything is sent.
    if (saved?.listeners.flow) {
      const fe = flowFormErrors(form, body.storage.retention_bytes);
      if (Object.keys(fe).length) {
        errors = fe;
        formError = `${Object.keys(fe).length === 1 ? 'One setting needs' : 'Some settings need'} fixing before saving.`;
        busy = false;
        await Promise.resolve();
        (document.querySelector('[aria-invalid="true"]') as HTMLElement | null)?.focus();
        return;
      }
    }
    sentLists = {
      'listeners.allowlist': body.listeners.allowlist,
      'listeners.blocklist': body.listeners.blocklist,
      // Communities by their hash, or "new community": a plain one is a secret.
      'listeners.snmp.communities': (body.listeners.snmp?.communities ?? []).map((c) => (isCommunityHash(c) ? c : 'new community')),
      'ui.extra_hostnames': body.ui.extra_hostnames,
      'ui.trusted_hosts': body.ui.trusted_hosts,
      'listeners.flow.rule_id_ies': body.listeners.flow?.rule_id_ies ?? [],
    };
    const prevSettings = saved ? $state.snapshot(saved) : null;
    const failingBefore = failingNow();
    try {
      const res = await putSettings(body, etag);
      saved = res.settings;
      form = toForm(saved);
      conflict = null;
      if (res.restarting) {
        const lan = saved.ui.lan_mode;
        // location.hostname keeps IPv6 brackets. Turning LAN mode off means localhost only.
        const url = lan ? `https://${location.hostname}:${saved.ui.port}/` : `http://localhost:${saved.ui.port}/`;
        moved = { url, lan, port: saved.ui.port };
        auth.movedTo = url;
      }
      savedAt = Date.now();
      saves++;
      setTimeout(() => (savedAt = 0), 2500);
      etag = res.etag;
      if (!auth.movedTo) {
        // A server that sends no ETag with the save: read the new one for the next save.
        if (!etag) etag = await getSettings().then((v) => v.etag, () => '');
        loadRejected();
        loadSession();
        // A save that breaks a listener (a port that's taken) offers "Undo last save".
        if (prevSettings) noteSave(prevSettings as Settings, failingBefore, etag);
        else refreshStatus();
      }
    } catch (x) {
      if (isConflict(x)) {
        conflict = { edits: saved ? edits(toForm(saved), form) : [], reloaded: false };
      } else if (x instanceof ApiError && Object.keys(x.fields).length) {
        errors = x.fields;
        formError = `${Object.keys(x.fields).length === 1 ? 'One setting needs' : 'Some settings need'} fixing before saving.`;
        await Promise.resolve();
        (document.querySelector('[aria-invalid="true"]') as HTMLElement | null)?.focus();
      } else {
        formError = (x as Error).message;
      }
    } finally {
      busy = false;
    }
  }

  function revert() {
    if (saved) form = toForm(saved);
    errors = {};
    formError = '';
  }

  const PROTOS = [
    { p: 'udp', label: 'UDP' },
    { p: 'tcp', label: 'TCP' },
  ] as const;
  const isWindows = $derived(live.status?.os.startsWith('windows') ?? false);
  const firewallCmd = (port: number) =>
    `netsh advfirewall firewall add rule name="Woodshed UI" dir=in action=allow protocol=TCP localport=${port}`;
  const passwordSet = $derived(!!auth.session?.password_set);
  const isMac = $derived(live.status?.os.startsWith('darwin') ?? false);
  const REASON: Record<string, string> = { allowlist: 'not on the allowlist', blocked: 'blocked', per_source: 'too many TCP connections', community: 'SNMP community not on the list' };

  // A refused sender with reason "blocked": Unblock takes its own entry out of the draft
  // blocklist; a broader range that covers it is named instead (only the user can judge it).
  const draftBlocklist = $derived(form ? parseAllowlist(form.blocklist) : []);
  const ownEntry = (ip: string) => draftBlocklist.find((c) => c === ip || c === hostCidr(ip));
  function coveringRange(ip: string): string {
    const v4 = (a: string) => (/^\d+\.\d+\.\d+\.\d+$/.test(a) ? a.split('.').reduce((n, p) => n * 256 + Number(p), 0) : null);
    const n = v4(ip);
    for (const c of draftBlocklist) {
      const [net, bits] = c.split('/');
      const b = v4(net);
      if (n === null || b === null || bits === undefined) continue;
      const k = Number(bits);
      const span = 2 ** (32 - k);
      if (Math.floor(n / span) === Math.floor(b / span)) return c;
    }
    return '';
  }
  function unblockInDraft(ip: string) {
    if (!form) return;
    form.blocklist = parseAllowlist(form.blocklist).filter((c) => c !== ip && c !== hostCidr(ip)).join('\n');
  }
  const reasonText = { age: 'older than the retention period', cap: 'disk cap reached', low_disk: 'low disk space' };
</script>

{#snippet firewall(port: number)}
  <div class="mt-3">
    <p class="m-0 text-[13.5px]">
      <b>Windows firewall:</b> allow the UI port so other machines can connect. Run this in a Command Prompt or PowerShell opened with
      <b>Run as administrator</b>:
    </p>
    <div class="log-panel mt-2 flex items-start gap-3 rounded-2xl p-3">
      <code class="grow text-[13px] leading-relaxed break-all whitespace-pre-wrap">{firewallCmd(port)}</code>
      <CopyButton text={firewallCmd(port)} />
    </div>
  </div>
{/snippet}

{#snippet fieldError(path: string)}
  {#if err(path)}<p class="ferr" id="err-{path}">{err(path)}</p>{/if}
{/snippet}

{#if loadError}
  <p class="card text-bad-fg" role="alert">Couldn't load settings: {loadError}</p>
{:else if !form}
  <p class="card text-muted">Loading…</p>
{:else}
  <form class="space-y-4" onsubmit={save} novalidate>
    <div class="savebar">
      <h1 class="m-0 text-xl font-bold tracking-tight">Settings</h1>
      <div class="flex items-center gap-2">
        <span class="text-[14px]" aria-live="polite">
          {#if savedAt}<span class="text-ok-fg">Saved.</span>{:else if dirty}<span class="text-muted">Unsaved changes</span>{/if}
        </span>
        <button type="button" class="ghost-btn" onclick={revert} disabled={!dirty || busy} title="Throw away the edits you haven't saved">Discard changes</button>
        <button type="submit" class="pill-btn" disabled={busy}>{busy ? 'Saving…' : 'Save'}</button>
      </div>
    </div>

    {#if undo.saved}
      <div class="undo" role="alert">
        <span>
          Your last save stopped a listener ({undo.saved.broke}): Woodshed can't receive logs there.
          {#if undo.error}<b>{undo.error}</b>{/if}
        </span>
        <button type="button" class="pill-btn" onclick={undoLastSave} disabled={undo.busy}>{undo.busy ? 'Undoing…' : 'Undo last save'}</button>
      </div>
    {/if}

    {#if conflict}
      <div class="conflict" role="alert">
        <p class="m-0 font-semibold">Settings changed elsewhere since you opened this page.</p>
        <p class="m-0 mt-1 text-[14px]">
          {#if conflict.reloaded}
            The form now shows the current settings. Your changes weren't saved: redo the ones you still want, then save.
          {:else}
            Your changes weren't saved. Reload to see the current settings; your changes stay listed here so you can redo them.
          {/if}
        </p>
        {#if conflict.edits.length}
          <ul class="edits" aria-label="Your unsaved changes">
            {#each conflict.edits as ed (ed.key)}
              <li>
                <b>{ed.label}</b>: yours <code>{ed.mine}</code>{#if conflict.reloaded && savedForm}, now <code>{shown(savedForm[ed.key])}</code>{/if}
              </li>
            {/each}
          </ul>
        {/if}
        <div class="mt-3 flex flex-wrap gap-2">
          {#if !conflict.reloaded}
            <button type="button" class="pill-btn" onclick={reloadAfterConflict} disabled={reloading}>{reloading ? 'Reloading…' : 'Reload'}</button>
          {/if}
          <button type="button" class="ghost-btn" onclick={() => (conflict = null)}>{conflict.reloaded ? 'Done' : 'Dismiss'}</button>
        </div>
      </div>
    {/if}

    {#if formError}
      <div class="rounded-2xl border border-[var(--error-border)] bg-[var(--error-bg)] px-4 py-3 text-[14px]" role="alert">
        {formError}
        {#each otherErrors as [k, m] (k)}
          <div class="mt-1"><code class="font-mono text-[13px]">{k}</code>: {m}</div>
        {/each}
      </div>
    {/if}

    {#if moved}
      <div class="moved" role="status">
        <p class="m-0 font-semibold">Woodshed is restarting its web UI at a new address.</p>
        <p class="m-0 mt-1 text-[14px]">
          {moved.lan ? 'LAN mode is on: the UI is now served over HTTPS and needs the password.' : 'The UI now answers only on this machine.'}
          This page stops updating; open the new address to carry on.
        </p>
        <div class="mt-3 flex flex-wrap items-center gap-3">
          <code class="font-mono text-[14px] font-semibold break-all">{moved.url}</code>
          <a class="pill-btn no-underline" href={moved.url}>Go there</a>
          <button type="button" class="ghost-btn" onclick={() => (moved = null)}>Dismiss</button>
        </div>
        {#if moved.lan}
          <p class="m-0 mt-3 text-[13.5px]">
            The browser will warn that the certificate isn't trusted, because Woodshed made it itself. That's expected the first time: check the address is
            this machine, then continue.
          </p>
        {/if}
        {#if moved.lan && isWindows}
          {@render firewall(moved.port)}
        {/if}
      </div>
    {/if}

    <section class="card">
      <h2 class="sec">Listeners</h2>
      <p class="hint mt-0">
        Where devices send syslog. Changes apply when you save; a port that's in use shows a banner.
        {#if isMac}On macOS, ports below 1024 can only be bound on all addresses (0.0.0.0 or ::).{/if}
      </p>
      {#each PROTOS as l (l.p)}
        <fieldset class="lst">
          <legend class="sr-only">{l.label} listener</legend>
          <label class="flex items-center gap-2 font-semibold">
            {#if l.p === 'udp'}
              <input type="checkbox" bind:checked={form.udpEnabled} aria-invalid={!!err('listeners.udp.enabled')} aria-describedby="err-listeners.udp.enabled" />
            {:else}
              <input type="checkbox" bind:checked={form.tcpEnabled} aria-invalid={!!err('listeners.tcp.enabled')} aria-describedby="err-listeners.tcp.enabled" />
            {/if}
            {l.label}
          </label>
          <label class="lbl">
            <span>Bind address</span>
            {#if l.p === 'udp'}
              <input class="field font-mono" bind:value={form.udpAddr} aria-invalid={!!err('listeners.udp.addr')} aria-describedby="err-listeners.udp.addr" spellcheck="false" />
            {:else}
              <input class="field font-mono" bind:value={form.tcpAddr} aria-invalid={!!err('listeners.tcp.addr')} aria-describedby="err-listeners.tcp.addr" spellcheck="false" />
            {/if}
            {@render fieldError(`listeners.${l.p}.addr`)}
          </label>
          <label class="lbl w-40">
            <span>Port</span>
            {#if l.p === 'udp'}
              <input class="field" type="number" bind:value={form.udpPort} aria-invalid={!!err('listeners.udp.port')} aria-describedby="err-listeners.udp.port" />
            {:else}
              <input class="field" type="number" bind:value={form.tcpPort} aria-invalid={!!err('listeners.tcp.port')} aria-describedby="err-listeners.tcp.port" />
            {/if}
            {@render fieldError(`listeners.${l.p}.port`)}
          </label>
          <div class="basis-full">{@render fieldError(`listeners.${l.p}.enabled`)}</div>
        </fieldset>
      {/each}
      <div class="lists mt-4">
      <label class="lbl">
        <span>Sender allowlist</span>
        <textarea
          class="field min-h-[84px] font-mono"
          bind:value={form.allowlist}
          placeholder="Empty: accept every sender. One CIDR per line, such as 10.1.0.0/16"
          aria-invalid={!!err('listeners.allowlist')}
          aria-describedby="err-listeners.allowlist"
          spellcheck="false"
        ></textarea>
        {@render fieldError('listeners.allowlist')}
        <span class="hint">Empty means every sender is accepted. Changes apply when you save.</span>
      </label>
      <label class="lbl" id="blocklist">
        <span>Blocklist</span>
        <textarea
          class="field min-h-[84px] font-mono"
          bind:value={form.blocklist}
          placeholder="Senders to refuse: one IP or CIDR per line, such as 198.51.100.0/24"
          aria-invalid={!!err('listeners.blocklist')}
          aria-describedby="err-listeners.blocklist"
          spellcheck="false"
        ></textarea>
        {@render fieldError('listeners.blocklist')}
        <span class="hint">Refused at the listener and counted; checked before the allowlist. Existing logs stay searchable.</span>
      </label>
      </div>

      <fieldset class="limits" id="sender-limits">
        <legend class="text-[14px] font-semibold">Sender limits</legend>
        <p class="hint mt-1">
          These protect against floods of fake source addresses, which would otherwise each become a device. Senders that already have logs
          on disk are never rate-limited; refused messages count as dropped.
        </p>
        <div class="grid gap-4 sm:grid-cols-3">
          <label class="lbl">
            <span>Active devices</span>
            <input class="field" type="number" min="1" bind:value={form.maxDevices} aria-invalid={!!err('listeners.max_devices')} aria-describedby="err-listeners.max_devices h-max" />
            <span class="hint" id="h-max">Devices that sent in the last 10 minutes. Default 10,000.</span>
            {@render fieldError('listeners.max_devices')}
          </label>
          <label class="lbl">
            <span>New senders at once</span>
            <input class="field" type="number" min="1" bind:value={form.burst} aria-invalid={!!err('listeners.new_device_burst')} aria-describedby="err-listeners.new_device_burst h-burst" />
            <span class="hint" id="h-burst">A burst of new addresses accepted before the rate applies. Default 5,000.</span>
            {@render fieldError('listeners.new_device_burst')}
          </label>
          <label class="lbl">
            <span>New senders per minute after that</span>
            <input class="field" type="number" min="1" bind:value={form.perMinute} aria-invalid={!!err('listeners.new_devices_per_minute')} aria-describedby="err-listeners.new_devices_per_minute h-rate" />
            <span class="hint" id="h-rate">The steady rate for brand-new addresses. Default 200.</span>
            {@render fieldError('listeners.new_devices_per_minute')}
          </label>
        </div>
      </fieldset>

      <h3 class="mt-4 mb-2 text-[14px] font-semibold">Refused senders, last 24 h</h3>
      {#if rejected === null}
        <p class="hint">Loading…</p>
      {:else if !rejected.length}
        <p class="hint">None. {saved?.listeners.allowlist.length ? 'Every sender is inside the allowlist.' : 'The allowlist is empty, so nothing is refused.'}</p>
      {:else}
        <div class="overflow-auto rounded-xl border border-[var(--divider)]">
          <table class="w-full border-collapse text-[13px]">
            <thead>
              <tr>
                <th scope="col">Sender</th>
                <th scope="col" class="text-right">Messages</th>
                <th scope="col">Last seen</th>
                <th scope="col">Why</th>
                <th scope="col"><span class="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {#each rejected as r (r.ip)}
                <tr>
                  <td class="font-mono">{r.ip}</td>
                  <td class="text-right tabular-nums">{num(r.count_24h)}</td>
                  <td title={dateTime(r.last_seen)}>{ago(r.last_seen, live.now)}</td>
                  <td>{REASON[r.reason] ?? r.reason}</td>
                  <td class="text-right">
                    <!-- Allowing only helps allowlist refusals; a per-source refusal is a connection flood. -->
                    {#if r.reason === 'allowlist'}
                      <button type="button" class="ghost-btn whitespace-nowrap" onclick={() => allow(r.ip)} disabled={inDraft(r.ip)} aria-label="Allow {r.ip}">
                        {inDraft(r.ip) ? 'Added, save to apply' : 'Allow'}
                      </button>
                    {:else if r.reason === 'blocked'}
                      {#if ownEntry(r.ip)}
                        <button type="button" class="ghost-btn whitespace-nowrap" onclick={() => unblockInDraft(r.ip)} aria-label="Unblock {r.ip}">Unblock</button>
                      {:else if coveringRange(r.ip)}
                        <span class="text-[12.5px] text-muted">Blocked by {coveringRange(r.ip)}</span>
                      {:else}
                        <span class="text-[12.5px] text-muted">Removed, save to apply</span>
                      {/if}
                    {/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>

    {#if saved?.listeners.tls}
      <section class="card" id="tls">
        <h2 class="sec">Syslog over TLS</h2>
        <p class="hint mt-0">
          A third listener, for devices that can encrypt their logs on the way (TCP with TLS). It's off until you turn it on. Devices import Woodshed's CA
          certificate once; a renewed certificate needs nothing on them.
        </p>
        <fieldset class="tlsrow">
          <legend class="sr-only">TLS listener</legend>
          <label class="flex items-center gap-2 font-semibold sw">
            <input type="checkbox" bind:checked={form.tlsEnabled} aria-invalid={!!err('listeners.tls.enabled')} aria-describedby="err-listeners.tls.enabled" />
            Syslog over TLS
          </label>
          <label class="lbl grow-1">
            <span>Bind address</span>
            <input class="field font-mono" bind:value={form.tlsAddr} aria-invalid={!!err('listeners.tls.addr')} aria-describedby="err-listeners.tls.addr" spellcheck="false" />
            {@render fieldError('listeners.tls.addr')}
          </label>
          <label class="lbl w-40">
            <span>TLS port</span>
            <input class="field" type="number" bind:value={form.tlsPort} aria-invalid={!!err('listeners.tls.port')} aria-describedby="err-listeners.tls.port hint-tlsport" />
            {@render fieldError('listeners.tls.port')}
          </label>
          <div class="basis-full">
            <span class="hint" id="hint-tlsport">Default 6514. Ports below 1024 need the same rights as 514.</span>
            {@render fieldError('listeners.tls.enabled')}
          </div>
        </fieldset>
        {#if form.tlsEnabled && !saved.listeners.tls.enabled}
          <div class="lanwarn" role="note">
            <b>Before you turn on TLS logging on a firewall:</b> some firewalls block traffic through them when a TLS syslog server can't be reached, or its
            certificate fails, unless an option permits traffic while the log host is down. Check that option first.
            {#if isWindows}On Windows, also run <code>woodshed tls on</code> once in an administrator prompt, so the firewall lets devices in.{/if}
          </div>
        {/if}

        <label class="mt-4 flex items-start gap-3">
          <input type="checkbox" bind:checked={form.tlsLegacy} aria-invalid={!!err('listeners.tls.allow_legacy_tls')} aria-describedby="hint-legacy err-listeners.tls.allow_legacy_tls" class="mt-1" />
          <span>
            <span class="font-semibold">Allow TLS 1.0 and 1.1</span>
            <span class="hint block" id="hint-legacy">
              For older senders that can't use TLS 1.2 or 1.3. A banner reminds you while it's on; turn it off once they're updated.
            </span>
          </span>
        </label>
        {@render fieldError('listeners.tls.allow_legacy_tls')}

        <fieldset class="src mt-4">
          <legend class="text-[14px] font-semibold">Certificate</legend>
          <label class="flex items-start gap-2 text-[14px]">
            <input type="radio" name="tls-source" value="woodshed" bind:group={form.tlsSource} class="mt-1" />
            <span>Woodshed's own CA <span class="hint">(recommended: devices import one CA certificate, and renewals don't change it)</span></span>
          </label>
          <label class="mt-1 flex items-start gap-2 text-[14px]">
            <input type="radio" name="tls-source" value="file" bind:group={form.tlsSource} class="mt-1" />
            <span>Your own certificate <span class="hint">(from your CA: a PEM chain and its key)</span></span>
          </label>
          {#if form.tlsSource === 'file'}
            <div class="mt-3 grid gap-4 sm:grid-cols-2">
              <label class="lbl">
                <span>TLS certificate file</span>
                <input class="field font-mono" bind:value={form.tlsCertFile} placeholder="/path/to/fullchain.pem" spellcheck="false" aria-invalid={!!err('listeners.tls.cert_file')} aria-describedby="err-listeners.tls.cert_file" />
                {@render fieldError('listeners.tls.cert_file')}
              </label>
              <label class="lbl">
                <span>TLS private key file</span>
                <input class="field font-mono" bind:value={form.tlsKeyFile} placeholder="/path/to/privkey.pem" spellcheck="false" aria-invalid={!!err('listeners.tls.key_file')} aria-describedby="err-listeners.tls.key_file" />
                {@render fieldError('listeners.tls.key_file')}
              </label>
            </div>
            <p class="hint mt-2 mb-0">
              Full paths on the machine running Woodshed. The certificate needs the serverAuth extended key usage (or none). Woodshed reads the files again
              on every save and on Retry.
            </p>
          {/if}
        </fieldset>

        <div class="mt-4">
          <TlsPanel enabled={saved.listeners.tls.enabled} port={saved.listeners.tls.port} reload={saves} />
        </div>
      </section>
    {/if}

    {#if saved?.listeners.snmp}
      <section class="card" id="snmp">
        <h2 class="sec">SNMP traps</h2>
        <p class="hint mt-0">
          A trap receiver on UDP, for devices that send SNMP traps and informs (v1, v2c and v3). It's off until you turn it on. Traps are stored beside
          each device's syslog, decoded as text with the packet kept, and searched in Events under SNMP traps.
        </p>
        <fieldset class="tlsrow">
          <legend class="sr-only">SNMP trap listener</legend>
          <label class="flex items-center gap-2 font-semibold sw">
            <input type="checkbox" bind:checked={form.snmpEnabled} aria-invalid={!!err('listeners.snmp.enabled')} aria-describedby="err-listeners.snmp.enabled" />
            SNMP traps
          </label>
          <label class="lbl grow-1">
            <span>Bind address</span>
            <input class="field font-mono" bind:value={form.snmpAddr} aria-invalid={!!err('listeners.snmp.addr')} aria-describedby="err-listeners.snmp.addr" spellcheck="false" />
            {@render fieldError('listeners.snmp.addr')}
          </label>
          <label class="lbl w-40">
            <span>UDP port</span>
            <input class="field" type="number" bind:value={form.snmpPort} aria-invalid={!!err('listeners.snmp.port')} aria-describedby="err-listeners.snmp.port hint-snmpport" />
            {@render fieldError('listeners.snmp.port')}
          </label>
          <div class="basis-full">
            <span class="hint" id="hint-snmpport">Default 162, often held by the OS's own trap service; any free port works. Ports below 1024 need the same rights as 514.</span>
            {@render fieldError('listeners.snmp.enabled')}
          </div>
        </fieldset>
        {#if form.snmpEnabled && !saved.listeners.snmp.enabled && isWindows}
          <div class="lanwarn" role="note">
            On Windows, also run <code>woodshed snmp on</code> once in an administrator prompt, so the firewall lets devices in on UDP {form.snmpPort}.
          </div>
        {/if}

        <label class="mt-4 flex items-start gap-3">
          <input type="checkbox" bind:checked={form.snmpInforms} aria-describedby="hint-informs err-listeners.snmp.answer_informs" class="mt-1" />
          <span>
            <span class="font-semibold">Answer informs</span>
            <span class="hint block" id="hint-informs">
              Reply to InformRequests once they're stored. An unanswered inform is sent again (and stored again), and the device may report the
              receiver as failing. Replies go only to allowed senders and are rate-limited.
            </span>
          </span>
        </label>
        {@render fieldError('listeners.snmp.answer_informs')}

        <div class="mt-4" id="snmp-communities">
          <span class="text-[14px] font-semibold">Communities (v1 and v2c)</span>
          <p class="hint mt-0 mb-2">
            Empty accepts any community. With a list, a trap with another community is refused and counted under refused senders. A community is often
            also the device's read password, so it's shown only as a hash prefix, never as text.
          </p>
          {#if form.snmpCommunities.length}
            <ul class="comms" aria-label="Accepted communities">
              {#each form.snmpCommunities as c, i (c + i)}
                <li>
                  <code>{isCommunityHash(c) ? c : 'new community'}</code>{#if !isCommunityHash(c)}<span class="hint m-0"> (saved when you press Save)</span>{/if}
                  <button
                    type="button"
                    class="x"
                    aria-label="Remove {isCommunityHash(c) ? c : 'the new community'}"
                    onclick={() => form && (form.snmpCommunities = form.snmpCommunities.filter((_, k) => k !== i))}>×</button
                  >
                </li>
              {/each}
            </ul>
          {/if}
          <div class="mt-2 flex flex-wrap items-center gap-2">
            <label class="sr-only" for="new-community">New community</label>
            <input id="new-community" class="field w-64" type="password" bind:value={newCommunity} autocomplete="off" placeholder="Add a community" onkeydown={(e) => e.key === 'Enter' && (e.preventDefault(), addCommunity())} />
            <button type="button" class="ghost-btn" onclick={addCommunity} disabled={!newCommunity}>Add</button>
          </div>
          {@render fieldError('listeners.snmp.communities')}
        </div>

        <div class="mt-4 grid gap-4 sm:grid-cols-2">
          <label class="lbl">
            <span>MIB folder</span>
            <input class="field font-mono" bind:value={form.snmpMibDir} placeholder="Empty: the mibs folder in the data folder" spellcheck="false" aria-invalid={!!err('listeners.snmp.mib_dir')} aria-describedby="err-listeners.snmp.mib_dir" />
            {@render fieldError('listeners.snmp.mib_dir')}
          </label>
          <label class="lbl">
            <span>Engine ID override</span>
            <input class="field font-mono" bind:value={form.snmpEngineId} placeholder="Empty: Woodshed's generated one" spellcheck="false" aria-invalid={!!err('listeners.snmp.engine_id')} aria-describedby="err-listeners.snmp.engine_id hint-engine" />
            <span class="hint m-0" id="hint-engine">Only for senders configured with a fixed receiver engine ID (hex, 5 to 32 bytes).</span>
            {@render fieldError('listeners.snmp.engine_id')}
          </label>
        </div>

        <div class="mt-4">
          <SnmpPanel enabled={saved.listeners.snmp.enabled} port={saved.listeners.snmp.port} reload={saves} />
        </div>
      </section>
    {/if}

    {#if saved?.listeners.flow}
      <section class="card" id="flows">
        <h2 class="sec">Flows</h2>
        <p class="hint mt-0">
          NetFlow v5, v9 and IPFIX from routers, switches and firewalls, kept beside their logs: who talked to whom, on which ports, how much, and the
          firewall's created, deleted and denied connections with their NAT. Both ports accept every version. Flows are searched in
          <a class="text-link underline" href="#/events?type=flow&r=1h">Events → Flows</a>.
        </p>
        <fieldset class="grid gap-4 sm:grid-cols-4">
          <legend class="sr-only">Flow listener</legend>
          <label class="flex items-center gap-2 font-semibold sm:col-span-4">
            <input type="checkbox" bind:checked={form.flowEnabled} aria-invalid={!!err('listeners.flow.enabled')} aria-describedby="err-listeners.flow.enabled" />
            Flows (NetFlow, IPFIX)
          </label>
          <label class="lbl">
            <span>Bind address</span>
            <input class="field font-mono" bind:value={form.flowAddr} spellcheck="false" aria-invalid={!!err('listeners.flow.addr')} aria-describedby="err-listeners.flow.addr" />
            {@render fieldError('listeners.flow.addr')}
          </label>
          <label class="lbl">
            <span>NetFlow port</span>
            <input class="field" type="number" min="0" max="65535" bind:value={form.flowNetflowPort} aria-invalid={!!err('listeners.flow.netflow_port')} aria-describedby="err-listeners.flow.netflow_port" />
            {@render fieldError('listeners.flow.netflow_port')}
          </label>
          <label class="lbl">
            <span>IPFIX port</span>
            <input class="field" type="number" min="0" max="65535" bind:value={form.flowIpfixPort} aria-invalid={!!err('listeners.flow.ipfix_port')} aria-describedby="err-listeners.flow.ipfix_port" />
            {@render fieldError('listeners.flow.ipfix_port')}
          </label>
          <label class="lbl">
            <span>Template timeout</span>
            <input class="field font-mono" bind:value={form.flowTimeout} spellcheck="false" aria-invalid={!!err('listeners.flow.template_timeout')} aria-describedby="err-listeners.flow.template_timeout hint-ftt" />
            {@render fieldError('listeners.flow.template_timeout')}
            <span class="hint" id="hint-ftt">A template not refreshed for this long expires (1m to 24h).</span>
          </label>
          <span class="hint sm:col-span-4">
            Defaults 2055 for NetFlow and 4739 for IPFIX; 0 turns one port off. The Windows installer adds the firewall rules "Woodshed flows (UDP 2055)"
            and "Woodshed flows (UDP 4739)" turned off; <code>woodshed flow on</code>, in an administrator prompt{isWindows ? '' : ' or with sudo'}, turns
            them on with the listener, and on Linux opens the ports in ufw or firewalld when one is active.
          </span>
          {@render fieldError('listeners.flow.enabled')}
        </fieldset>
        <div class="mt-4 grid gap-4 sm:grid-cols-2">
          <label class="lbl">
            <span>Rule ID fields</span>
            <textarea id="flow-rule-ies" class="field font-mono" rows="3" bind:value={form.flowRuleIes} spellcheck="false" placeholder="32473:7"
              aria-invalid={!!err('listeners.flow.rule_id_ies')} aria-describedby="err-listeners.flow.rule_id_ies hint-frid"></textarea>
            {@render fieldError('listeners.flow.rule_id_ies')}
            <span class="hint" id="hint-frid">
              Up to 8, one per line, as enterprise number:element ID. The first one a record has becomes its rule ID, which you can filter on and rank in
              Top. There's no standard field for it; find your exporter's below.
            </span>
          </label>
          <label class="lbl">
            <span>Flow budget (GiB)</span>
            <input class="field" type="number" min="0" step="any" bind:value={form.flowBudgetGiB} aria-invalid={!!err('storage.flow_budget_bytes')} aria-describedby="err-storage.flow_budget_bytes hint-fbud" />
            {@render fieldError('storage.flow_budget_bytes')}
            <span class="hint" id="hint-fbud">
              0 keeps the default, 40 % of the disk cap ({bytes(budgetOf(0, Math.round(n(form.retentionGiB) * GiB)))} now). Flows over their budget are
              deleted first, oldest first, so they never push your other logs out; at most 90 % of the cap.
              {#if n(form.flowBudgetGiB)}This budget: {bytes(budgetOf(Math.round(n(form.flowBudgetGiB) * GiB), 0))}.{/if}
            </span>
          </label>
        </div>
        <div class="mt-4">
          <FlowStatePanel reload={saves} ruleIes={ruleIesOf(form.flowRuleIes)} onuse={(k) => form && (form.flowRuleIes = [...ruleIesOf(form.flowRuleIes), k].join('\n'))} />
        </div>
      </section>
    {/if}

    {#if saved?.poll}
      <section class="card" id="polling">
        <h2 class="sec">Polling</h2>
        <p class="hint mt-0">
          SNMP polling of the devices you add on the <a class="text-link underline" href="#/devices?view=polled">Devices page</a>: uptime, interface
          traffic and errors, CPU and memory, graphed beside their logs. These are the defaults; each device can override its interval, presets and
          interfaces. With no polled devices, Woodshed sends no SNMP requests.
        </p>
        <div class="grid gap-4 sm:grid-cols-3">
          <label class="lbl">
            <span>Poll every (seconds)</span>
            <input class="field" type="number" min="30" max="600" bind:value={form.pollInterval} aria-invalid={!!err('poll.interval_s')} aria-describedby="err-poll.interval_s hint-piv" />
            <span class="hint" id="hint-piv">30 s to 10 min. Default 60.</span>
            {@render fieldError('poll.interval_s')}
          </label>
          <label class="lbl">
            <span>Timeout (ms)</span>
            <input class="field" type="number" min="200" max="10000" step="100" bind:value={form.pollTimeoutMs} aria-invalid={!!err('poll.timeout_ms')} aria-describedby="err-poll.timeout_ms hint-pto" />
            <span class="hint" id="hint-pto">Per request. Default 2,000.</span>
            {@render fieldError('poll.timeout_ms')}
          </label>
          <label class="lbl">
            <span>Retries</span>
            <input class="field" type="number" min="0" max="5" bind:value={form.pollRetries} aria-invalid={!!err('poll.retries')} aria-describedby="err-poll.retries hint-prt" />
            <span class="hint" id="hint-prt">0 to 5. Default 1.</span>
            {@render fieldError('poll.retries')}
          </label>
          <label class="lbl">
            <span>Interfaces per device</span>
            <input class="field" type="number" min="1" max="1024" bind:value={form.pollMaxIf} aria-invalid={!!err('poll.max_interfaces')} aria-describedby="err-poll.max_interfaces hint-pmi" />
            <span class="hint" id="hint-pmi">Pinned first, then up, fastest first. Default 64.</span>
            {@render fieldError('poll.max_interfaces')}
          </label>
          <label class="lbl">
            <span>Devices polled at once</span>
            <input class="field" type="number" min="1" max="256" bind:value={form.pollConcurrency} aria-invalid={!!err('poll.concurrency')} aria-describedby="err-poll.concurrency hint-pcc" />
            <span class="hint" id="hint-pcc">Raise it if cycles are skipped. Default 32.</span>
            {@render fieldError('poll.concurrency')}
          </label>
          <label class="lbl">
            <span>Most polled devices</span>
            <input class="field" type="number" min="1" max="5000" bind:value={form.pollMaxTargets} aria-invalid={!!err('poll.max_targets')} aria-describedby="err-poll.max_targets hint-pmt" />
            <span class="hint" id="hint-pmt">Default 500.</span>
            {@render fieldError('poll.max_targets')}
          </label>
        </div>
        <fieldset class="mt-2 border-0 p-0">
          <legend class="text-[13.5px] font-medium">Default presets for new devices</legend>
          <div class="mt-1 flex flex-wrap gap-x-5 gap-y-1">
            {#each POLL_PRESETS as p (p.key)}
              <label class="flex items-center gap-2 text-[14px]" title={p.hint}><input type="checkbox" value={p.key} bind:group={form.pollPresets} />{p.label}</label>
            {/each}
          </div>
          {@render fieldError('poll.presets')}
        </fieldset>
        <div class="mt-4"><PollStatePanel /></div>
      </section>
    {/if}

    <section class="card">
      <h2 class="sec" id="storage">Storage</h2>
      <p class="hint mt-0">Logs are deleted oldest first when either limit is reached. If the disk runs low, Woodshed deletes more, and never fills it.</p>
      <label class="lbl">
        <span>Data folder</span>
        <input class="field font-mono" value={form.dataDir} readonly aria-invalid={!!err('storage.data_dir')} aria-describedby="err-storage.data_dir hint-datadir" />
        <span class="hint" id="hint-datadir">Set in the config file; moving it needs a restart.</span>
        {@render fieldError('storage.data_dir')}
      </label>
      <div class="mt-3 grid gap-4 sm:grid-cols-3">
        <label class="lbl">
          <span>Keep logs for (days)</span>
          <input class="field" type="number" min="1" bind:value={form.retentionDays} aria-invalid={!!err('storage.retention_days')} aria-describedby="err-storage.retention_days" />
          {@render fieldError('storage.retention_days')}
        </label>
        <label class="lbl">
          <span>Disk cap (GiB)</span>
          <input class="field" type="number" min="1" step="any" bind:value={form.retentionGiB} aria-invalid={!!err('storage.retention_bytes')} aria-describedby="err-storage.retention_bytes" />
          {@render fieldError('storage.retention_bytes')}
        </label>
        <div class="estimate sm:col-span-3" aria-live="polite" data-estimate>
          {#if est === undefined}
            <span class="text-muted">Estimating…</span>
          {:else if est === null || est.estimated_days === null}
            <span class="text-muted">Not enough data yet for an estimate: it needs about an hour of logs.</span>
          {:else}
            <b>{bytes(Math.round(n(form.retentionGiB) * GiB))} {approxDays(est.estimated_days)}</b> at the current rate
            {#if est.bytes_per_day !== null}(≈ {bytes(est.bytes_per_day)}/day){/if}.
            {#if est.estimated_days < n(form.retentionDays)}
              <span class="cap">The size cap is reached first, so logs are kept for {approxDays(est.estimated_days).replace('≈ ', 'about ')}, not {n(form.retentionDays)} days.</span>
            {:else}
              The {n(form.retentionDays)}-day limit is reached first.
            {/if}
          {/if}
        </div>
        <label class="lbl">
          <span>Split files at (MiB)</span>
          <input class="field" type="number" min="1" step="any" bind:value={form.partMiB} aria-invalid={!!err('storage.part_bytes')} aria-describedby="err-storage.part_bytes" />
          {@render fieldError('storage.part_bytes')}
        </label>
      </div>

      <p class="hint mt-3">
        Both limits apply: logs are kept for the number of days you set <i>or</i> until the size cap is full, whichever comes first.
      </p>
      <details class="examples">
        <summary class="text-[14px] font-semibold">How long does {bytes(Math.round(n(form.retentionGiB) * GiB))} last?</summary>
        <p class="hint mt-2">Typical syslog compresses to about 25 bytes a message on disk. Your own rate is in the estimate above.</p>
        <table class="ex">
          <thead><tr><th scope="col">Messages a second</th><th scope="col" class="text-right">On disk a day</th><th scope="col" class="text-right">{bytes(Math.round(n(form.retentionGiB) * GiB))} lasts</th></tr></thead>
          <tbody>
            {#each [100, 1000, 10000] as r (r)}
              <tr>
                <td>{num(r)}</td>
                <td class="text-right tabular-nums">{bytes(r * 25 * 86400)}</td>
                <td class="text-right tabular-nums">{approxDays((n(form.retentionGiB) * GiB) / (r * 25 * 86400))}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </details>

      <h3 class="mt-5 mb-2 text-[14px] font-semibold">Storage history</h3>
      {#if history === null}
        <p class="hint">Loading…</p>
      {:else if !history.length}
        <p class="hint">Nothing has been deleted yet.</p>
      {:else}
        <div class="max-h-64 overflow-auto rounded-xl border border-[var(--divider)]">
          <table class="w-full border-collapse text-[13px]">
            <thead>
              <tr><th scope="col">Deleted</th><th scope="col">File</th><th scope="col">Device</th><th scope="col" class="text-right">Size</th><th scope="col">Why</th></tr>
            </thead>
            <tbody>
              {#each history as h (h.time + h.file)}
                <tr>
                  <td class="whitespace-nowrap">{dateTime(h.time)}</td>
                  <td class="font-mono break-all">{h.file}</td>
                  <td>{deviceName(h.device_id)}</td>
                  <td class="text-right whitespace-nowrap tabular-nums">{bytes(h.bytes)}</td>
                  <td>{reasonText[h.reason] ?? h.reason}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>

    <section class="card">
      <h2 class="sec">UI access</h2>
      <label class="flex items-start gap-3">
        <input
          type="checkbox"
          bind:checked={form.lanMode}
          disabled={!passwordSet && !form.lanMode}
          aria-invalid={!!err('ui.lan_mode')}
          aria-describedby="hint-lan err-ui.lan_mode"
          class="mt-1"
        />
        <span>
          <span class="font-semibold">LAN mode</span>
          <span class="hint block" id="hint-lan">
            {#if saved?.ui.lan_mode}
              On: other machines can open this UI over HTTPS, with the password.
            {:else}
              Off: the UI is only reachable from this machine, on localhost:{saved?.ui.port}.
              {#if !passwordSet}Set a password below to turn it on.{/if}
            {/if}
          </span>
        </span>
      </label>
      {@render fieldError('ui.lan_mode')}
      {#if form.lanMode && !saved?.ui.lan_mode}
        <div class="lanwarn" role="note">
          <b>Before you turn this on:</b> anyone on your network who can reach this machine will see the Woodshed login page, and with the password,
          all of your logs. Use a strong password. Browsers will warn about the certificate the first time, because Woodshed creates its own
          (self-signed) certificate; that's expected, not an attack, as long as the address is this machine.
          {#if isWindows}Windows also needs a firewall rule for the UI port; the command is shown after you save.{/if}
        </div>
      {/if}
      {#if saved?.ui.lan_mode && isWindows}
        {@render firewall(saved.ui.port)}
      {/if}
      {#if saved?.ui.lan_mode && live.status?.ui_cert_fingerprint}
        <div class="fp mt-3">
          <p class="m-0 text-[13.5px]">
            <b>Certificate fingerprint (SHA-256).</b> When the browser warns about the certificate, open its details and check the SHA-256
            fingerprint matches this one. If it doesn't, you aren't talking to this Woodshed.
          </p>
          <div class="mt-2 flex flex-wrap items-center gap-2">
            <code class="font-mono text-[12.5px] break-all">{live.status.ui_cert_fingerprint}</code>
            <CopyButton text={live.status.ui_cert_fingerprint} />
          </div>
        </div>
      {/if}

      <label class="mt-4 flex items-start gap-3">
        <input
          type="checkbox"
          bind:checked={form.requireLocal}
          disabled={!passwordSet && !form.requireLocal}
          aria-invalid={!!err('ui.require_login_local')}
          aria-describedby="hint-local err-ui.require_login_local"
          class="mt-1"
        />
        <span>
          <span class="font-semibold">Require login on this machine too</span>
          <span class="hint block" id="hint-local">
            For shared or multi-user machines: anyone logged in to this computer can otherwise open the UI on localhost without a password.
            {#if !passwordSet}Set a password below first.{/if}
          </span>
        </span>
      </label>
      {@render fieldError('ui.require_login_local')}

      <label class="lbl mt-3 w-40">
        <span>UI port</span>
        <input class="field" type="number" bind:value={form.uiPort} aria-invalid={!!err('ui.port')} aria-describedby="err-ui.port" />
        {@render fieldError('ui.port')}
      </label>

      <div class="lists mt-4">
        <label class="lbl">
          <span>Extra certificate names</span>
          <textarea
            class="field min-h-[72px] font-mono"
            bind:value={form.extraHostnames}
            placeholder="One per line, such as logs.example.net"
            aria-invalid={!!err('ui.extra_hostnames')}
            aria-describedby="err-ui.extra_hostnames hint-extra"
            spellcheck="false"
          ></textarea>
          {@render fieldError('ui.extra_hostnames')}
          <span class="hint" id="hint-extra">
            For LAN mode: other names this machine is reached by. The hostname, its local and search-domain names, and its addresses are covered
            already. Adding a name regenerates Woodshed's own certificate, so browsers warn about it once more.
          </span>
          {#if addsCertName && form.lanMode && !form.certFile}
            <span class="note" role="note">After you save, the certificate is regenerated: browsers warn once more, and the fingerprint changes.</span>
          {/if}
        </label>
        <label class="lbl">
          <span>Trusted host names</span>
          <textarea
            class="field min-h-[72px] font-mono"
            bind:value={form.trustedHosts}
            placeholder="One per line: a host or host:port, such as logs.example.net:443"
            aria-invalid={!!err('ui.trusted_hosts')}
            aria-describedby="err-ui.trusted_hosts hint-trusted"
            spellcheck="false"
          ></textarea>
          {@render fieldError('ui.trusted_hosts')}
          <span class="hint" id="hint-trusted">
            For a reverse proxy in front of the UI: the names it forwards as the Host header. Exact names only; other names are refused.
          </span>
        </label>
      </div>

      <details class="adv mt-4" open={!!(form.certFile || form.keyFile || err('ui.cert_file') || err('ui.key_file'))}>
        <summary class="cursor-pointer text-[14px] font-semibold">Advanced: use your own certificate</summary>
        <p class="hint mt-2">
          For LAN mode. Leave both empty to use the certificate Woodshed generates. Paths are on the machine running Woodshed (PEM files).
        </p>
        <div class="grid gap-4 sm:grid-cols-2">
          <label class="lbl">
            <span>Certificate file</span>
            <input class="field font-mono" bind:value={form.certFile} placeholder="/path/to/cert.pem" spellcheck="false" aria-invalid={!!err('ui.cert_file')} aria-describedby="err-ui.cert_file" />
            {@render fieldError('ui.cert_file')}
          </label>
          <label class="lbl">
            <span>Private key file</span>
            <input class="field font-mono" bind:value={form.keyFile} placeholder="/path/to/key.pem" spellcheck="false" aria-invalid={!!err('ui.key_file')} aria-describedby="err-ui.key_file" />
            {@render fieldError('ui.key_file')}
          </label>
        </div>
      </details>

      <PasswordForm onchange={load} />
    </section>

    <section class="card">
      <h2 class="sec">Quiet devices</h2>
      <p class="hint mt-0">A device's dot turns amber when nothing has arrived for a while, and red after longer.</p>
      <div class="grid gap-4 sm:grid-cols-2">
        <label class="lbl">
          <span><span class="dot" style:background="var(--warn)" aria-hidden="true"></span>Quiet after (minutes)</span>
          <input class="field" type="number" min="0.5" step="any" bind:value={form.quietMin} aria-invalid={!!err('quiet.quiet_after_seconds')} aria-describedby="err-quiet.quiet_after_seconds" />
          {@render fieldError('quiet.quiet_after_seconds')}
        </label>
        <label class="lbl">
          <span><span class="dot" style:background="var(--bad)" aria-hidden="true"></span>Offline after (minutes)</span>
          <input class="field" type="number" min="1" step="any" bind:value={form.offlineMin} aria-invalid={!!err('quiet.offline_after_seconds')} aria-describedby="err-quiet.offline_after_seconds" />
          {@render fieldError('quiet.offline_after_seconds')}
        </label>
      </div>
    </section>

    <UpdatesSettings onchange={adoptEtag} />
  </form>
{/if}

<style>
  .undo {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 12px 16px;
    border-radius: 18px;
    border: 1px solid var(--error-border);
    background: var(--error-bg);
    font-size: 14px;
  }
  .savebar {
    position: sticky;
    top: 8px;
    z-index: 5;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 10px 12px 10px 18px;
    border-radius: 999px;
    background: var(--glass-strong);
    border: 1px solid var(--border);
    -webkit-backdrop-filter: blur(16px);
    backdrop-filter: blur(16px);
  }
  .conflict {
    padding: 16px 18px;
    border-radius: 22px;
    border: 1px solid var(--warn-border);
    background: var(--warn-bg);
  }
  .conflict .edits {
    margin: 8px 0 0;
    padding-left: 20px;
    font-size: 14px;
  }
  .conflict code {
    font-family: var(--font-mono);
    font-size: 13px;
    overflow-wrap: anywhere;
  }
  .note {
    font-size: 13px;
    font-weight: 600;
    color: var(--warn-fg);
  }
  .moved {
    padding: 16px 18px;
    border-radius: 22px;
    border: 1px solid var(--info-border);
    background: var(--info-bg);
  }
  #storage,
  #tls {
    scroll-margin-top: 90px;
  }
  .tlsrow {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-start;
    gap: 12px 18px;
    border: 0;
    border-top: 1px solid var(--divider);
    padding: 14px 0 4px;
    margin: 0;
  }
  .tlsrow .sw {
    padding-top: 30px;
    min-width: 160px;
  }
  .tlsrow .grow-1 {
    flex: 1;
    min-width: 200px;
  }
  .tlsrow .hint {
    margin: 0;
  }
  .src {
    border: 0;
    border-top: 1px solid var(--divider);
    margin: 18px 0 0;
    padding: 14px 0 0;
  }
  .src legend {
    padding: 0;
    margin-bottom: 6px;
  }
  .lanwarn code {
    font-family: var(--font-mono);
    font-size: 12.5px;
  }
  .estimate {
    padding: 10px 14px;
    border-radius: 14px;
    background: var(--glass-strong);
    border: 1px solid var(--border);
    font-size: 14px;
  }
  .estimate .cap {
    color: var(--warn-fg);
    font-weight: 600;
  }
  .examples {
    margin-top: 8px;
  }
  .examples summary {
    cursor: pointer;
  }
  table.ex {
    border-collapse: collapse;
    font-size: 13.5px;
    margin-top: 4px;
  }
  table.ex th,
  table.ex td {
    padding: 5px 14px 5px 0;
  }
  .lists {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
  }
  @media (max-width: 720px) {
    .lists {
      grid-template-columns: 1fr;
    }
  }
  #blocklist {
    scroll-margin-top: 90px;
  }
  .limits {
    /* Land below the sticky save bar when the device_limit banner links here. */
    scroll-margin-top: 90px;
    border: 0;
    border-top: 1px solid var(--divider);
    margin: 18px 0 0;
    padding: 14px 0 0;
  }
  .fp {
    padding: 10px 14px;
    border-radius: 14px;
    border: 1px solid var(--info-border);
    background: var(--info-bg);
  }
  .lanwarn {
    margin-top: 10px;
    padding: 10px 14px;
    border-radius: 14px;
    border: 1px solid var(--warn-border);
    background: var(--warn-bg);
    font-size: 13.5px;
    line-height: 1.5;
  }
  .adv summary::marker {
    color: var(--muted);
  }
  .field[readonly] {
    background: transparent;
    border-style: dashed;
  }
  .sec {
    margin: 0 0 6px;
    font-size: 17px;
    font-weight: 700;
  }
  .hint {
    font-size: 13px;
    color: var(--muted);
    margin-bottom: 10px;
  }
  .lbl {
    display: flex;
    flex-direction: column;
    gap: 5px;
    font-size: 13.5px;
    font-weight: 500;
  }
  .lbl > .hint {
    margin: 0;
    font-weight: 400;
  }
  .lst {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-start;
    gap: 12px 18px;
    border: 0;
    border-top: 1px solid var(--divider);
    padding: 14px 0 4px;
    margin: 0;
  }
  .lst > label:first-of-type {
    width: 80px;
    padding-top: 30px;
  }
  .lst > .lbl:not(.w-40) {
    flex: 1;
    min-width: 200px;
  }
  .ferr {
    white-space: pre-line;
    margin: 2px 0 0;
    font-size: 13px;
    font-weight: 500;
    color: var(--bad-fg);
  }
  .dot {
    display: inline-block;
    width: 9px;
    height: 9px;
    border-radius: 50%;
    margin-right: 6px;
  }
  th {
    text-align: left;
    font-weight: 600;
    color: var(--muted);
    padding: 6px 10px;
    border-bottom: 1px solid var(--divider);
    position: sticky;
    top: 0;
    background: var(--glass-strong);
  }
  td {
    padding: 6px 10px;
    border-bottom: 1px solid var(--divider);
  }
  #snmp,
  #snmp-communities {
    scroll-margin-top: 90px;
  }
  .comms {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin: 0;
    padding: 0;
    list-style: none;
  }
  .comms li {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 2px 4px 2px 10px;
    border-radius: 999px;
    background: var(--chip);
    border: 1px solid var(--border);
    font-size: 12.5px;
  }
  .comms code {
    font-family: var(--font-mono);
  }
  .comms .x {
    border: 0;
    background: none;
    cursor: pointer;
    color: var(--muted);
    font-size: 15px;
    line-height: 1;
    padding: 0 4px;
  }
</style>
