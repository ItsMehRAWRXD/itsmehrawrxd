// CerebralIDE Easter Egg Handler
// Handles the magical animations triggered by hidden hex codes

import React, { useEffect, useState } from 'react';
import { usePubSub } from '../hooks/usePubSub';

interface EasterEggEvent {
  type: 'confetti_burst' | 'golden_rain' | 'rainbow_wave';
  data: {
    duration: number;
    message: string;
    colors?: string[];
  };
}

export function EasterEggHandler() {
  const [activeAnimation, setActiveAnimation] = useState<EasterEggEvent | null>(null);
  const [billingOverride, setBillingOverride] = useState(false);

  // Listen for Easter egg events from the Meta-Engine
  usePubSub('easter_egg', (event: EasterEggEvent) => {
    console.log('🎉 Easter egg triggered:', event);
    setActiveAnimation(event);
    
    // Auto-clear animation after duration
    setTimeout(() => {
      setActiveAnimation(null);
    }, event.data.duration);
  });

  // Listen for billing override events
  usePubSub('billing_override', (event: { active: boolean; duration: number }) => {
    setBillingOverride(event.active);
    
    if (event.active) {
      setTimeout(() => {
        setBillingOverride(false);
      }, event.duration * 1000);
    }
  });

  return (
    <>
      {/* Confetti Burst Animation */}
      {activeAnimation?.type === 'confetti_burst' && (
        <ConfettiBurst
          duration={activeAnimation.data.duration}
          message={activeAnimation.data.message}
          colors={activeAnimation.data.colors || []}
        />
      )}

      {/* Golden Rain Animation */}
      {activeAnimation?.type === 'golden_rain' && (
        <GoldenRain
          duration={activeAnimation.data.duration}
          message={activeAnimation.data.message}
        />
      )}

      {/* Rainbow Wave Animation */}
      {activeAnimation?.type === 'rainbow_wave' && (
        <RainbowWave
          duration={activeAnimation.data.duration}
          message={activeAnimation.data.message}
        />
      )}

      {/* Billing Override Indicator */}
      {billingOverride && (
        <div className="billing-override-indicator">
          💰 Demo Mode: Billing Zero-Rated
        </div>
      )}
    </>
  );
}

// Confetti Burst Component
function ConfettiBurst({ duration, message, colors }: {
  duration: number;
  message: string;
  colors: string[];
}) {
  const [particles, setParticles] = useState<Array<{
    id: number;
    x: number;
    y: number;
    vx: number;
    vy: number;
    color: string;
    rotation: number;
  }>>([]);

  useEffect(() => {
    // Generate confetti particles
    const newParticles = Array.from({ length: 150 }, (_, i) => ({
      id: i,
      x: Math.random() * window.innerWidth,
      y: -10,
      vx: (Math.random() - 0.5) * 8,
      vy: Math.random() * 3 + 2,
      color: colors[Math.floor(Math.random() * colors.length)],
      rotation: Math.random() * 360,
    }));

    setParticles(newParticles);

    // Animate particles
    const interval = setInterval(() => {
      setParticles(prev => 
        prev.map(particle => ({
          ...particle,
          x: particle.x + particle.vx,
          y: particle.y + particle.vy,
          vy: particle.vy + 0.1, // gravity
          rotation: particle.rotation + 5,
        })).filter(particle => particle.y < window.innerHeight + 50)
      );
    }, 16);

    return () => clearInterval(interval);
  }, [colors]);

  return (
    <div className="confetti-burst-overlay">
      <div className="confetti-message">
        {message}
      </div>
      {particles.map(particle => (
        <div
          key={particle.id}
          className="confetti-particle"
          style={{
            position: 'absolute',
            left: particle.x,
            top: particle.y,
            width: '8px',
            height: '8px',
            backgroundColor: particle.color,
            transform: `rotate(${particle.rotation}deg)`,
            borderRadius: '50%',
            pointerEvents: 'none',
            zIndex: 9999,
          }}
        />
      ))}
    </div>
  );
}

// Golden Rain Component
function GoldenRain({ duration, message }: {
  duration: number;
  message: string;
}) {
  const [drops, setDrops] = useState<Array<{
    id: number;
    x: number;
    y: number;
    speed: number;
  }>>([]);

  useEffect(() => {
    const newDrops = Array.from({ length: 100 }, (_, i) => ({
      id: i,
      x: Math.random() * window.innerWidth,
      y: -10,
      speed: Math.random() * 3 + 1,
    }));

    setDrops(newDrops);

    const interval = setInterval(() => {
      setDrops(prev => 
        prev.map(drop => ({
          ...drop,
          y: drop.y + drop.speed,
        })).filter(drop => drop.y < window.innerHeight + 50)
      );
    }, 16);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="golden-rain-overlay">
      <div className="golden-message">
        {message}
      </div>
      {drops.map(drop => (
        <div
          key={drop.id}
          className="golden-drop"
          style={{
            position: 'absolute',
            left: drop.x,
            top: drop.y,
            width: '2px',
            height: '20px',
            background: 'linear-gradient(to bottom, #ffd700, #ffed4e)',
            pointerEvents: 'none',
            zIndex: 9999,
          }}
        />
      ))}
    </div>
  );
}

// Rainbow Wave Component
function RainbowWave({ duration, message }: {
  duration: number;
  message: string;
}) {
  const [waveOffset, setWaveOffset] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setWaveOffset(prev => (prev + 1) % 360);
    }, 16);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="rainbow-wave-overlay">
      <div className="rainbow-message">
        {message}
      </div>
      <div
        className="rainbow-wave"
        style={{
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: `linear-gradient(${waveOffset}deg, 
            #ff0000, #ff7f00, #ffff00, #00ff00, 
            #0000ff, #4b0082, #9400d3, #ff0000)`,
          opacity: 0.3,
          pointerEvents: 'none',
          zIndex: 9998,
        }}
      />
    </div>
  );
}

// CSS for the animations
const styles = `
.confetti-burst-overlay,
.golden-rain-overlay,
.rainbow-wave-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  pointer-events: none;
  z-index: 9999;
}

.confetti-message,
.golden-message,
.rainbow-message {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  font-size: 2rem;
  font-weight: bold;
  text-align: center;
  color: white;
  text-shadow: 2px 2px 4px rgba(0,0,0,0.8);
  z-index: 10000;
  animation: pulse 1s ease-in-out infinite alternate;
}

@keyframes pulse {
  from { transform: translate(-50%, -50%) scale(1); }
  to { transform: translate(-50%, -50%) scale(1.1); }
}

.billing-override-indicator {
  position: fixed;
  top: 20px;
  right: 20px;
  background: #00ff00;
  color: #000;
  padding: 10px 20px;
  border-radius: 5px;
  font-weight: bold;
  z-index: 10001;
  animation: blink 1s ease-in-out infinite alternate;
}

@keyframes blink {
  from { opacity: 0.7; }
  to { opacity: 1; }
}
`;

// Inject styles
if (typeof document !== 'undefined') {
  const styleSheet = document.createElement('style');
  styleSheet.textContent = styles;
  document.head.appendChild(styleSheet);
}
