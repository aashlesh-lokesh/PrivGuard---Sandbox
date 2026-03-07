/**
 * Custom compromise.js plugin for PrivGuard
 * Adds domain-specific sensitive phrase and OTP context recognition.
 */

const privguardPlugin = {
  words: {
    // Treat these nouns as sensitive-context markers
    confidential:   'SensitiveAdj',
    secret:         'SensitiveAdj',
    private:        'SensitiveAdj',
    restricted:     'SensitiveAdj',
    classified:     'SensitiveAdj',
    proprietary:    'SensitiveAdj',
    'do not share': 'SensitivePhrase',
    'not for distribution': 'SensitivePhrase',
  },
  tags: {
    SensitiveAdj: {
      isA: 'Adjective',
    },
    SensitivePhrase: {
      isA: 'Phrase',
    },
  },
};

export default privguardPlugin;
