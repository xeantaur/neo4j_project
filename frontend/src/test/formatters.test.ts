import { describe, it, expect } from 'vitest';
import {
  formatObservedBytes,
  formatObservedPackets,
  formatEpochSeconds,
  formatObservationWindow,
} from '../utils/formatters';

describe('Formatters Utility', () => {
  describe('formatObservedBytes', () => {
    it('handles null and undefined', () => {
      expect(formatObservedBytes(null)).toBe('—');
      expect(formatObservedBytes(undefined)).toBe('—');
    });

    it('formats bytes below 1 KiB', () => {
      expect(formatObservedBytes(0)).toBe('0 B');
      expect(formatObservedBytes(512)).toBe('512 B');
      expect(formatObservedBytes(1023)).toBe('1023 B');
    });

    it('formats bytes in KiB and MiB', () => {
      expect(formatObservedBytes(1024)).toBe('1.00 KiB');
      expect(formatObservedBytes(1536)).toBe('1.50 KiB');
      expect(formatObservedBytes(1048576)).toBe('1.00 MiB');
      expect(formatObservedBytes(1048576 * 2.5)).toBe('2.50 MiB');
    });
  });

  describe('formatObservedPackets', () => {
    it('handles null and undefined', () => {
      expect(formatObservedPackets(null)).toBe('—');
      expect(formatObservedPackets(undefined)).toBe('—');
    });

    it('formats numbers with digit grouping', () => {
      expect(formatObservedPackets(0)).toBe('0');
      expect(formatObservedPackets(100)).toBe('100');
      expect(formatObservedPackets(1234567)).toBe('1,234,567');
    });
  });

  describe('formatEpochSeconds', () => {
    it('handles null and undefined', () => {
      expect(formatEpochSeconds(null)).toBe('—');
      expect(formatEpochSeconds(undefined)).toBe('—');
    });

    it('formats valid epoch timestamp into ISO 8601 string', () => {
      expect(formatEpochSeconds(0)).toBe('1970-01-01T00:00:00.000Z');
      expect(formatEpochSeconds(1718000000)).toBe('2024-06-10T06:13:20.000Z');
    });
  });

  describe('formatObservationWindow', () => {
    it('handles null and undefined', () => {
      expect(formatObservationWindow(null)).toBe('—');
      expect(formatObservationWindow(undefined)).toBe('—');
    });

    it('formats sub-second and multi-second durations', () => {
      expect(formatObservationWindow(0.005)).toBe('5 ms');
      expect(formatObservationWindow(0.5)).toBe('500 ms');
      expect(formatObservationWindow(1.0)).toBe('1.00s');
      expect(formatObservationWindow(12.3456)).toBe('12.35s');
    });
  });
});
