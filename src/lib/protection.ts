// Protection summary derived strictly from reported fields. Shared by the app
// header and the Overview page so both always tell the same story.

import type { SystemStatus } from '../api/types';

export interface ProtectionSummary {
  label: 'Protected' | 'Attention needed' | 'Unprotected' | 'Unknown';
  tone: 'good' | 'warn' | 'bad' | 'neutral';
  reasons: string[];
}

export function summarizeProtection(status: SystemStatus | null | undefined): ProtectionSummary {
  if (!status) {
    return {
      label: 'Unknown',
      tone: 'neutral',
      reasons: ['No status has been received from the engine yet.'],
    };
  }
  const reasons: string[] = [];
  const engine = status.engine;
  const engineRunning = typeof engine?.running === 'boolean' ? engine.running : null;
  const defender = status.defender;

  if (engineRunning === null) {
    reasons.push('The engine did not report whether it is running.');
  } else if (!engineRunning) {
    reasons.push('The security engine process is not running.');
  }

  if (!defender?.available) {
    reasons.push(
      defender?.queryError
        ? `Defender status is unavailable: ${defender.queryError}`
        : 'Microsoft Defender status could not be read.',
    );
  } else {
    if (!defender.realtimeEnabled) {
      reasons.push('Defender real-time protection is disabled.');
    }
    if (!defender.antivirusEnabled) {
      reasons.push('Defender antivirus protection is disabled.');
    }
    if (!defender.tamperProtected) {
      reasons.push('Defender tamper protection is not enabled.');
    }
  }

  const defenderGood =
    defender?.available === true && defender.realtimeEnabled && defender.antivirusEnabled;
  const engineGood = engineRunning === true;

  if (engineGood && defenderGood) {
    return {
      label: 'Protected',
      tone: 'good',
      reasons: ['Engine monitoring and Defender real-time protection are active.'],
    };
  }
  const engineBad = engineRunning === false;
  const defenderBad =
    defender?.available === true && (!defender.realtimeEnabled || !defender.antivirusEnabled);
  if (engineBad || defenderBad) {
    return { label: 'Unprotected', tone: 'bad', reasons };
  }
  return { label: 'Attention needed', tone: 'warn', reasons };
}
