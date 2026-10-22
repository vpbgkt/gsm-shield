'use strict';

const { START, normalizeImagePath, parseRegQuery, assessServices, makeBaseline } = require('./service-integrity');

const env = { SystemRoot: 'C:\\WINDOWS', ProgramFiles: 'C:\\Program Files' };

describe('normalizeImagePath', () => {
  test.each([
    ['C:\\WINDOWS\\System32\\OpenSSH\\ssh-agent.exe', 'C:\\WINDOWS\\System32\\OpenSSH\\ssh-agent.exe'],
    ['"C:\\Program Files\\App\\svc.exe" -service', 'C:\\Program Files\\App\\svc.exe'],
    ['%SystemRoot%\\System32\\svchost.exe -k netsvcs -p', 'C:\\WINDOWS\\System32\\svchost.exe'],
    ['\\SystemRoot\\System32\\drivers\\x.sys', 'C:\\WINDOWS\\System32\\drivers\\x.sys'],
    ['system32\\DriverStore\\FileRepository\\a\\b.exe', 'C:\\WINDOWS\\system32\\DriverStore\\FileRepository\\a\\b.exe'],
    ['%ProgramFiles%\\Foo\\bar.exe /run', 'C:\\Program Files\\Foo\\bar.exe'],
  ])('%s', (input, expected) => {
    expect(normalizeImagePath(input, env)).toBe(expected);
  });

  test('empty input', () => {
    expect(normalizeImagePath('', env)).toBeNull();
    expect(normalizeImagePath(null, env)).toBeNull();
  });
});

describe('parseRegQuery', () => {
  const text = [
    'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\ssh-agent',
    '    Start    REG_DWORD    0x2',
    '',
    'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\ssh-agent\\Security',
    '    Start    REG_DWORD    0x4',
    '',
    'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\PIEServiceNew',
    '    Start    REG_DWORD    0x2',
    '',
    'End of search: 3 match(es) found.',
  ].join('\r\n');

  test('keeps only direct children of Services and parses DWORDs', () => {
    expect(parseRegQuery(text, 'Start')).toEqual({ 'ssh-agent': 2, PIEServiceNew: 2 });
  });

  test('parses string values', () => {
    const t = 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\x\r\n    ImagePath    REG_EXPAND_SZ    "C:\\a b\\x.exe" -k\r\n';
    expect(parseRegQuery(t, 'ImagePath')).toEqual({ x: '"C:\\a b\\x.exe" -k' });
  });
});

describe('assessServices', () => {
  const analyze = (p) => ({ verdict: /infected/i.test(p) ? 'infected' : 'clean' });
  const exists = (p) => !/missing/i.test(p);

  test('flags infected service binaries as critical', () => {
    const { findings, checked } = assessServices([
      { name: 'PIEServiceNew', start: START.AUTO, imagePath: '"C:\\x\\infected_Intel_PIE_Service.exe"' },
      { name: 'Good', start: START.AUTO, imagePath: 'C:\\x\\good.exe' },
    ], { analyze, exists });
    expect(checked).toBe(2);
    expect(findings).toEqual([expect.objectContaining({ service: 'PIEServiceNew', type: 'binary-infected', severity: 'critical' })]);
  });

  test('flags disabled/manual -> auto escalation against a baseline (Expiro event 7040 pattern)', () => {
    const baseline = makeBaseline([{ name: 'ssh-agent', start: START.DISABLED }, { name: 'MidiSrv', start: START.MANUAL }]);
    const { findings } = assessServices([
      { name: 'ssh-agent', start: START.AUTO, imagePath: 'C:\\WINDOWS\\System32\\OpenSSH\\ssh-agent.exe' },
      { name: 'MidiSrv', start: START.MANUAL, imagePath: 'C:\\WINDOWS\\System32\\MidiSrv.exe' },
    ], { analyze, exists, baseline });
    expect(findings).toEqual([expect.objectContaining({ service: 'ssh-agent', type: 'start-type-escalated', severity: 'high' })]);
  });

  test('without a baseline, a normally-disabled service set to Auto is reported', () => {
    const { findings } = assessServices([{ name: 'ssh-agent', start: START.AUTO, imagePath: 'C:\\w\\ssh-agent.exe' }], { analyze, exists });
    expect(findings[0]).toMatchObject({ type: 'unexpected-auto-start', severity: 'medium' });
  });

  test('missing binaries are informational; svchost and drivers are skipped', () => {
    const { findings, checked } = assessServices([
      { name: 'sppsvc', start: START.AUTO, imagePath: 'C:\\WINDOWS\\system32\\missing_sppsvc.exe' },
      { name: 'Dhcp', start: START.AUTO, imagePath: '%SystemRoot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted' },
      { name: 'disk', start: START.BOOT, imagePath: 'System32\\drivers\\disk.sys' },
    ], { analyze, exists });
    expect(checked).toBe(0);
    expect(findings).toEqual([expect.objectContaining({ service: 'sppsvc', type: 'binary-missing', severity: 'info' })]);
  });
});
