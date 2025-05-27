import { describe, it, expect, beforeEach, vi } from 'vitest';

describe('window.location.assign mock', () => {
  beforeEach(() => {
    // Reset the mock before each test
    (window.location.assign as any).mockReset();
  });

  it('should be able to mock window.location.assign', () => {
    // Call the mocked function
    window.location.assign('https://example.com');
    
    // Verify it was called with the expected URL
    expect(window.location.assign).toHaveBeenCalledTimes(1);
    expect(window.location.assign).toHaveBeenCalledWith('https://example.com');
  });

  it('should track multiple calls to window.location.assign', () => {
    // Call the mocked function multiple times
    window.location.assign('https://example.com/page1');
    window.location.assign('https://example.com/page2');
    
    // Verify all calls
    expect(window.location.assign).toHaveBeenCalledTimes(2);
    expect(window.location.assign).toHaveBeenNthCalledWith(1, 'https://example.com/page1');
    expect(window.location.assign).toHaveBeenNthCalledWith(2, 'https://example.com/page2');
  });
});