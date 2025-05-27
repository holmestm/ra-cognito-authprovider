import { describe, it, expect } from 'vitest';
import {
  formIsLogin,
  formIsNewPassword,
  formIsTotp,
  formIsTotpAssociation,
} from '../localLogin/useCognitoLogin';

describe('Form type utilities', () => {
  describe('formIsLogin', () => {
    it('should identify login form data', () => {
      expect(formIsLogin({ username: 'test', password: 'password' })).toBe(true);
    });

    it('should reject non-login form data', () => {
      expect(formIsLogin({ newPassword: 'password', confirmNewPassword: 'password' })).toBe(false);
      expect(formIsLogin({ totp: '123456' })).toBe(false);
      expect(formIsLogin({ association: 'code' })).toBe(false);
    });
  });

  describe('formIsNewPassword', () => {
    it('should identify new password form data', () => {
      expect(formIsNewPassword({ newPassword: 'password', confirmNewPassword: 'password' })).toBe(true);
    });

    it('should reject non-new-password form data', () => {
      expect(formIsNewPassword({ username: 'test', password: 'password' })).toBe(false);
      expect(formIsNewPassword({ totp: '123456' })).toBe(false);
      expect(formIsNewPassword({ association: 'code' })).toBe(false);
    });
  });

  describe('formIsTotp', () => {
    it('should identify TOTP form data', () => {
      expect(formIsTotp({ totp: '123456' })).toBe(true);
    });

    it('should reject non-TOTP form data', () => {
      expect(formIsTotp({ username: 'test', password: 'password' })).toBe(false);
      expect(formIsTotp({ newPassword: 'password', confirmNewPassword: 'password' })).toBe(false);
      expect(formIsTotp({ association: 'code' })).toBe(false);
    });
  });

  describe('formIsTotpAssociation', () => {
    it('should identify TOTP association form data', () => {
      expect(formIsTotpAssociation({ association: 'code' })).toBe(true);
    });

    it('should reject non-TOTP-association form data', () => {
      expect(formIsTotpAssociation({ username: 'test', password: 'password' })).toBe(false);
      expect(formIsTotpAssociation({ newPassword: 'password', confirmNewPassword: 'password' })).toBe(false);
      expect(formIsTotpAssociation({ totp: '123456' })).toBe(false);
    });
  });
});