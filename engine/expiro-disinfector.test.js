'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const ExpiroDisinfector = require('./expiro-disinfector');
const { cleanMsvc64, expiroInfected64 } = require('./__tests__/helpers/pe-builder');

const sha = (p) => crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');

describe('ExpiroDisinfector (v3 policy: no in-place patching)', () => {
  let dir;
  let trusted;
  let quarantined;
  let quarantine;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'disinfect-'));
    trusted = path.join(dir, 'trusted');
    fs.mkdirSync(trusted);
    quarantined = [];
    quarantine = {
      quarantineFile: jest.fn(async (p, threat) => {
        const dest = path.join(dir, `q_${quarantined.length}.gsmq`);
        fs.copyFileSync(p, dest);
        fs.unlinkSync(p);
        quarantined.push({ p, threat, dest });
        return { quarantinePath: dest };
      }),
    };
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  test('protected Windows paths are never touched', async () => {
    const d = new ExpiroDisinfector(quarantine);
    const r = await d.disinfectFile('C:\\Windows\\System32\\OpenSSH\\ssh-agent.exe', { threatName: 'x' });
    expect(r.action).toBe('system_protected');
    expect(r.recommendation).toMatch(/DISM/);
    expect(quarantine.quarantineFile).not.toHaveBeenCalled();
  });

  test('without a trusted source the infected file is quarantined, never modified in place', async () => {
    const infected = path.join(dir, 'tool.exe');
    fs.writeFileSync(infected, expiroInfected64());
    const before = sha(infected);
    const d = new ExpiroDisinfector(quarantine);
    const r = await d.disinfectFile(infected, { threatName: 'Virus:Win64/Expiro (structural)' });
    expect(r.action).toBe('quarantined');
    expect(r.success).toBe(true);
    expect(r.recommendation).toMatch(/Reinstall/);
    expect(sha(quarantined[0].dest)).toBe(before); // stored exactly as found
    expect(fs.existsSync(infected)).toBe(false);
  });

  test('a verified same-build clean copy is restored', async () => {
    const infected = path.join(dir, 'clamscan.exe');
    fs.writeFileSync(infected, expiroInfected64({ timeDateStamp: 0x12345678 }));
    fs.writeFileSync(path.join(trusted, 'clamscan.exe'), cleanMsvc64({ timeDateStamp: 0x12345678 }));
    const d = new ExpiroDisinfector(quarantine, { trustedSourceDirs: [trusted] });
    const r = await d.disinfectFile(infected, { threatName: 't' });
    expect(r.action).toBe('restored');
    expect(r.success).toBe(true);
    expect(r.verification).toBe('clean');
    expect(sha(infected)).toBe(sha(path.join(trusted, 'clamscan.exe')));
  });

  test('a clean copy of a different build is rejected and the file is quarantined', async () => {
    const infected = path.join(dir, 'app.exe');
    fs.writeFileSync(infected, expiroInfected64({ timeDateStamp: 1 }));
    fs.writeFileSync(path.join(trusted, 'app.exe'), cleanMsvc64({ timeDateStamp: 2 }));
    const d = new ExpiroDisinfector(quarantine, { trustedSourceDirs: [trusted] });
    const r = await d.disinfectFile(infected, {});
    expect(r.action).toBe('quarantined');
    expect(r.rejectedCandidates[0]).toMatch(/different build/);
  });

  test('an infected "clean source" is rejected', async () => {
    const infected = path.join(dir, 'b.exe');
    fs.writeFileSync(infected, expiroInfected64({ timeDateStamp: 7 }));
    fs.writeFileSync(path.join(trusted, 'b.exe'), expiroInfected64({ timeDateStamp: 7 }));
    const d = new ExpiroDisinfector(quarantine, { trustedSourceDirs: [trusted] });
    const r = await d.disinfectFile(infected, {});
    expect(r.action).toBe('quarantined');
    expect(r.rejectedCandidates[0]).toMatch(/not structurally clean/);
  });

  test('batch processes non-critical files before critical ones', async () => {
    const a = path.join(dir, 'a.exe');
    fs.writeFileSync(a, expiroInfected64());
    const d = new ExpiroDisinfector(quarantine);
    const order = [];
    const res = await d.disinfectBatch(
      [{ filePath: 'C:\\Windows\\System32\\x.exe' }, { filePath: a }],
      (p) => order.push(p.file)
    );
    expect(order).toEqual([a, 'C:\\Windows\\System32\\x.exe']);
    expect(res.quarantined).toBe(1);
    expect(res.failed).toBe(1);
  });
});
