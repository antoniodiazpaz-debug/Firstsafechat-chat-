/* Funktionstest des extrahierten crypto-core.js Moduls — X3DH-Handshake
   und Double-Ratchet-Rundlauf, damit die Extraktion nichts kaputt
   gemacht hat. */
import { webcrypto } from 'node:crypto';
globalThis.window = { crypto: webcrypto };

const M = await import('./public/crypto-core.js');
const { P, PreKeys, X3DH, Ratchet } = M;

let pass = 0, fail = 0;
const ok = (c, m) => { c ? (pass++, console.log('  ✓', m)) : (fail++, console.log('  ✗', m)) };

console.log('Prekeys:');
const storeA = await PreKeys.createStore();
const storeB = await PreKeys.createStore();
ok(!!storeA.IK && !!storeA.IKS && !!storeA.SPK, 'Store enthält IK, IKS, SPK');
ok(storeA.opks.size === 10, '10 One-Time Prekeys erzeugt');
const bundleA = PreKeys.bundle(storeA);
ok(!!bundleA.spkSig, 'Bundle enthält Signatur');
const verified = await PreKeys.verifyBundle(bundleA);
ok(verified.ok, 'eigenes Bundle verifiziert sich selbst');

console.log('\nX3DH-Handshake:');
const bundleB = PreKeys.bundle(storeB);
const { SK, EK, usedOpkId } = await X3DH.initiator(storeA.IK, bundleB);
ok(!!SK, 'Initiator leitet Startgeheimnis ab');
const usedOpk = await PreKeys.consumeOPK(storeB, usedOpkId);
const SK2 = await X3DH.responder(storeB.IK, storeB.SPK, usedOpk, storeA.IK.pubJwk, EK.pubJwk);
const hexs = M.hexs;
ok(hexs(SK) === hexs(SK2), 'beide Seiten leiten dasselbe Geheimnis ab');

console.log('\nDouble Ratchet Rundlauf:');
const stA = await Ratchet.initSender(SK, bundleB.spk);
const stB = Ratchet.initReceiver(SK2, storeB.SPK);
const te = M.te, td = M.td;
const env = await Ratchet.encrypt(stA, te.encode('Testnachricht'), 'aad');
const dec = td.decode(await Ratchet.decrypt(stB, env, 'aad'));
ok(dec === 'Testnachricht', 'Nachricht korrekt verschlüsselt und entschlüsselt');

console.log('\nRichtungswechsel:');
const reply = await Ratchet.encrypt(stB, te.encode('Antwort'), 'aad2');
ok(stB.dhSteps === 1, 'Empfänger hat beim ersten Senden geratcheted');
const decReply = td.decode(await Ratchet.decrypt(stA, reply, 'aad2'));
ok(decReply === 'Antwort', 'Antwort korrekt entschlüsselt');

console.log(`\n${pass} bestanden, ${fail} fehlgeschlagen`);
process.exit(fail ? 1 : 0);
