module.exports = {
  port: process.env.PORT || 3001,
  host: process.env.HOST || 'localhost',
  environment: process.env.NODE_ENV || 'development',
  security: {
    enableCORS: true,
    enableHelmet: true,
    enableRateLimit: true
  },
  database: {
    type: 'builtin',
    path: './data'
  },
  irc: {
    enabled: true,
    server: 'irc.libera.chat',
    port: 6667,
    channels: ['#rawrz-test'],
    nickname: 'RawrZBot',
    username: 'rawrz',
    realname: 'RawrZ Security Bot'
  },
  encryption: {
    defaultAlgorithm: 'aes-256-gcm',
    keyDerivation: 'pbkdf2'
  },
  enterprise: {
    enabled: true,
    features: {
      stubGeneration: true,
      botBuilder: true,
      encryption: true,
      jottiScanning: true,
      ircBot: true,
      htmlBot: true
    }
  }
};
