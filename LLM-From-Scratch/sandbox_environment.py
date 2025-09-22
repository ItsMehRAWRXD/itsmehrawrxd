#!/usr/bin/env python3
"""
AI Sandbox Environment with Template Support
This module provides a flexible sandbox environment that can be configured
using templates, allowing AI agents to train in various scenarios.
"""

import gymnasium as gym
from gymnasium import spaces
import numpy as np
import random
import json
import socket
import threading
import time
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum

class NPCBehaviorType(Enum):
    WANDER = "wander"
    CHASE = "chase"
    PATROL = "patrol"
    PASSIVE = "passive"
    AGGRESSIVE = "aggressive"

class RewardStructureType(Enum):
    DISTANCE_BASED = "distance_based"
    EXPLORATION_BASED = "exploration_based"
    SURVIVAL_BASED = "survival_based"
    GOAL_BASED = "goal_based"
    TIME_BASED = "time_based"

class DifficultyLevel(Enum):
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    EXTREME = "extreme"

class EnvironmentType(Enum):
    OPEN_WORLD = "open_world"
    MAZE = "maze"
    COMBAT = "combat"
    TRAINING = "training"
    PUZZLE = "puzzle"
    SURVIVAL = "survival"

@dataclass
class SandboxTemplate:
    name: str
    size: int = 10
    wall_density: float = 0.1
    npc_count: int = 1
    npc_behavior: str = "wander"
    reward_structure: str = "distance_based"
    difficulty: str = "medium"
    environment_type: str = "open_world"
    special_rules: Dict[str, Any] = None

    def __post_init__(self):
        if self.special_rules is None:
            self.special_rules = {}

class FreeroamTemplateEnv(gym.Env):
    """
    A flexible sandbox environment that can be configured using templates.
    This allows AI agents to train in various scenarios with different
    layouts, NPCs, and reward structures.
    """
    
    metadata = {"render_modes": ["human", "rgb_array"], "render_fps": 4}

    def __init__(self, render_mode=None, template=None):
        super().__init__()
        
        # Apply the provided template or use a default one
        self.template = template if template else self._get_default_template()
        self.size = self.template.size
        self.window_size = 512
        self.render_mode = render_mode

        # Define spaces based on the template size
        self.observation_space = spaces.Dict({
            "player": spaces.Box(0, self.size - 1, shape=(2,), dtype=int),
            "target": spaces.Box(0, self.size - 1, shape=(2,), dtype=int),
            "npcs": spaces.Box(0, self.size - 1, shape=(self.template.npc_count, 2), dtype=int),
            "map": spaces.Box(0, 1, shape=(self.size, self.size), dtype=int),
        })
        
        self.action_space = spaces.Discrete(4)

        self._action_to_direction = {
            0: np.array([1, 0]),   # Right
            1: np.array([-1, 0]),  # Left
            2: np.array([0, 1]),   # Up
            3: np.array([0, -1]),  # Down
        }

        # Initialize game state
        self._player_location = None
        self._target_location = None
        self._npc_locations = None
        self._npc_behaviors = None
        self.map = None
        self._step_count = 0
        self._max_steps = self._calculate_max_steps()

    def _get_default_template(self):
        return SandboxTemplate(
            name="default",
            size=10,
            wall_density=0.1,
            npc_count=1,
            npc_behavior="wander",
            reward_structure="distance_based",
            difficulty="medium",
            environment_type="open_world"
        )

    def _calculate_max_steps(self):
        """Calculate maximum steps based on template difficulty and size."""
        base_steps = self.size * 2
        difficulty_multiplier = {
            "easy": 1.5,
            "medium": 1.0,
            "hard": 0.7,
            "extreme": 0.5
        }
        return int(base_steps * difficulty_multiplier.get(self.template.difficulty, 1.0))

    def _generate_map_from_template(self):
        """Generate the map based on template parameters."""
        map = np.zeros((self.size, self.size), dtype=int)
        
        if self.template.wall_density > 0:
            for i in range(self.size):
                for j in range(self.size):
                    if random.random() < self.template.wall_density:
                        map[i, j] = 1

        # Ensure player and target positions are not blocked
        map[0, 0] = 0  # Player starting position
        map[self.size-1, self.size-1] = 0  # Target position
        
        return map

    def _initialize_npc_behaviors(self):
        """Initialize NPC behaviors based on template."""
        behaviors = []
        for i in range(self.template.npc_count):
            behavior_type = NPCBehaviorType(self.template.npc_behavior)
            behaviors.append({
                'type': behavior_type,
                'state': 'idle',
                'target': None,
                'patrol_points': self._generate_patrol_points() if behavior_type == NPCBehaviorType.PATROL else None,
                'patrol_index': 0
            })
        return behaviors

    def _generate_patrol_points(self):
        """Generate patrol points for NPCs."""
        points = []
        for _ in range(3):
            x = random.randint(0, self.size - 1)
            y = random.randint(0, self.size - 1)
            if self.map[x, y] == 0:  # Only place on empty spaces
                points.append(np.array([x, y]))
        return points

    def _calculate_reward(self, action):
        """Calculate reward based on template reward structure."""
        reward = 0
        
        if self.template.reward_structure == "distance_based":
            # Reward for getting closer to target
            distance = np.linalg.norm(self._player_location - self._target_location, ord=1)
            max_distance = self.size * 2
            reward = (max_distance - distance) / max_distance * 10
            
        elif self.template.reward_structure == "exploration_based":
            # Reward for exploring new areas
            reward = 1.0 if self._is_new_position() else -0.1
            
        elif self.template.reward_structure == "survival_based":
            # Reward for surviving and avoiding NPCs
            reward = 1.0
            for npc_loc in self._npc_locations:
                if np.array_equal(self._player_location, npc_loc):
                    reward = -10.0
                    break
                    
        elif self.template.reward_structure == "goal_based":
            # Reward only for reaching the target
            reward = 10.0 if np.array_equal(self._player_location, self._target_location) else -0.1
            
        elif self.template.reward_structure == "time_based":
            # Reward for efficiency (reaching target quickly)
            reward = 1.0 / (self._step_count + 1)
        
        # Apply difficulty modifier
        difficulty_multiplier = {
            "easy": 1.2,
            "medium": 1.0,
            "hard": 0.8,
            "extreme": 0.6
        }
        reward *= difficulty_multiplier.get(self.template.difficulty, 1.0)
        
        return reward

    def _is_new_position(self):
        """Check if current position is new (for exploration reward)."""
        # Simplified: assume all positions are new for now
        # In a real implementation, you'd track visited positions
        return True

    def _update_npc_behaviors(self):
        """Update NPC behaviors based on their type."""
        for i, (npc_loc, behavior) in enumerate(zip(self._npc_locations, self._npc_behaviors)):
            if behavior['type'] == NPCBehaviorType.WANDER:
                self._update_wander_behavior(i, npc_loc, behavior)
            elif behavior['type'] == NPCBehaviorType.CHASE:
                self._update_chase_behavior(i, npc_loc, behavior)
            elif behavior['type'] == NPCBehaviorType.PATROL:
                self._update_patrol_behavior(i, npc_loc, behavior)
            elif behavior['type'] == NPCBehaviorType.PASSIVE:
                # Passive NPCs don't move
                pass
            elif behavior['type'] == NPCBehaviorType.AGGRESSIVE:
                self._update_aggressive_behavior(i, npc_loc, behavior)

    def _update_wander_behavior(self, npc_index, npc_loc, behavior):
        """Update wander behavior for an NPC."""
        if random.random() < 0.3:  # 30% chance to move
            direction = random.choice(list(self._action_to_direction.values()))
            new_location = np.clip(npc_loc + direction, 0, self.size - 1)
            if self.map[tuple(new_location)] == 0:  # Check if not blocked
                self._npc_locations[npc_index] = new_location

    def _update_chase_behavior(self, npc_index, npc_loc, behavior):
        """Update chase behavior for an NPC."""
        # Move towards player
        direction = self._player_location - npc_loc
        if np.any(direction != 0):
            # Normalize direction to unit movement
            move_x = 1 if direction[0] > 0 else (-1 if direction[0] < 0 else 0)
            move_y = 1 if direction[1] > 0 else (-1 if direction[1] < 0 else 0)
            new_location = np.clip(npc_loc + np.array([move_x, move_y]), 0, self.size - 1)
            if self.map[tuple(new_location)] == 0:  # Check if not blocked
                self._npc_locations[npc_index] = new_location

    def _update_patrol_behavior(self, npc_index, npc_loc, behavior):
        """Update patrol behavior for an NPC."""
        if behavior['patrol_points'] and len(behavior['patrol_points']) > 0:
            target_point = behavior['patrol_points'][behavior['patrol_index']]
            direction = target_point - npc_loc
            
            if np.all(direction == 0):  # Reached patrol point
                behavior['patrol_index'] = (behavior['patrol_index'] + 1) % len(behavior['patrol_points'])
            else:
                # Move towards patrol point
                move_x = 1 if direction[0] > 0 else (-1 if direction[0] < 0 else 0)
                move_y = 1 if direction[1] > 0 else (-1 if direction[1] < 0 else 0)
                new_location = np.clip(npc_loc + np.array([move_x, move_y]), 0, self.size - 1)
                if self.map[tuple(new_location)] == 0:  # Check if not blocked
                    self._npc_locations[npc_index] = new_location

    def _update_aggressive_behavior(self, npc_index, npc_loc, behavior):
        """Update aggressive behavior for an NPC."""
        # Aggressive NPCs chase the player more aggressively
        if random.random() < 0.7:  # 70% chance to move (higher than wander)
            direction = self._player_location - npc_loc
            if np.any(direction != 0):
                move_x = 1 if direction[0] > 0 else (-1 if direction[0] < 0 else 0)
                move_y = 1 if direction[1] > 0 else (-1 if direction[1] < 0 else 0)
                new_location = np.clip(npc_loc + np.array([move_x, move_y]), 0, self.size - 1)
                if self.map[tuple(new_location)] == 0:  # Check if not blocked
                    self._npc_locations[npc_index] = new_location

    def reset(self, seed=None, options=None):
        super().reset(seed=seed)
        
        # Generate map from template
        self.map = self._generate_map_from_template()
        
        # Initialize player position
        self._player_location = np.array([0, 0])
        
        # Initialize target position
        self._target_location = np.array([self.size - 1, self.size - 1])
        
        # Initialize NPC positions
        self._npc_locations = []
        for i in range(self.template.npc_count):
            # Place NPCs randomly on empty spaces
            while True:
                x = random.randint(0, self.size - 1)
                y = random.randint(0, self.size - 1)
                if self.map[x, y] == 0 and not np.array_equal([x, y], self._player_location):
                    self._npc_locations.append(np.array([x, y]))
                    break
        
        # Initialize NPC behaviors
        self._npc_behaviors = self._initialize_npc_behaviors()
        
        # Reset step count
        self._step_count = 0
        
        observation = self._get_obs()
        info = self._get_info()
        
        if self.render_mode == "human":
            self.render()
            
        return observation, info

    def step(self, action):
        self._step_count += 1
        
        # Move player
        direction = self._action_to_direction[action]
        new_player_location = np.clip(self._player_location + direction, 0, self.size - 1)
        
        # Check if new position is blocked
        if self.map[tuple(new_player_location)] == 0:
            self._player_location = new_player_location
        
        # Update NPC behaviors
        self._update_npc_behaviors()
        
        # Calculate reward
        reward = self._calculate_reward(action)
        
        # Check termination conditions
        terminated = np.array_equal(self._player_location, self._target_location)
        truncated = self._step_count >= self._max_steps
        
        observation = self._get_obs()
        info = self._get_info()
        
        if self.render_mode == "human":
            self.render()
            
        return observation, reward, terminated, truncated, info

    def _get_obs(self):
        return {
            "player": self._player_location,
            "target": self._target_location,
            "npcs": np.array(self._npc_locations),
            "map": self.map
        }

    def _get_info(self):
        return {
            "step_count": self._step_count,
            "max_steps": self._max_steps,
            "template": asdict(self.template),
            "player_location": self._player_location.tolist(),
            "target_location": self._target_location.tolist(),
            "npc_locations": [loc.tolist() for loc in self._npc_locations]
        }

    def render(self):
        if self.render_mode == "human":
            grid = np.full((self.size, self.size), '.', dtype=str)
            
            # Place walls
            for i in range(self.size):
                for j in range(self.size):
                    if self.map[i, j] == 1:
                        grid[i, j] = '#'
            
            # Place player
            grid[tuple(self._player_location)] = 'P'
            
            # Place target
            grid[tuple(self._target_location)] = 'T'
            
            # Place NPCs
            for i, npc_loc in enumerate(self._npc_locations):
                grid[tuple(npc_loc)] = str(i + 1)
            
            print("\n" + "="*50)
            print(f"Step: {self._step_count}/{self._max_steps}")
            print(f"Template: {self.template.name}")
            print("="*50)
            for row in grid:
                print(" ".join(row))
            print("="*50)
            print("Legend: P=Player, T=Target, 1,2,3...=NPCs, #=Wall")
            print()

    def close(self):
        pass

class SandboxServer:
    """
    Server that manages sandbox environments and communicates with C# clients.
    """
    
    def __init__(self, host='127.0.0.1', port=65433):
        self.host = host
        self.port = port
        self.environments = {}
        self.running = False
        
    def start(self):
        """Start the sandbox server."""
        self.running = True
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()
            print(f"Sandbox server listening on {self.host}:{self.port}")
            
            while self.running:
                try:
                    conn, addr = s.accept()
                    client_thread = threading.Thread(
                        target=self._handle_client, 
                        args=(conn, addr)
                    )
                    client_thread.start()
                except Exception as e:
                    if self.running:
                        print(f"Error accepting connection: {e}")
    
    def stop(self):
        """Stop the sandbox server."""
        self.running = False
    
    def _handle_client(self, conn, addr):
        """Handle a client connection."""
        print(f"Connected by {addr}")
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                
                request = json.loads(data.decode('utf-8'))
                response = self._process_request(request)
                
                conn.sendall(json.dumps(response).encode('utf-8'))
                
        except Exception as e:
            print(f"Error handling client {addr}: {e}")
        finally:
            conn.close()
    
    def _process_request(self, request):
        """Process a client request."""
        action = request.get('action')
        
        try:
            if action == 'create_environment':
                return self._create_environment(request)
            elif action == 'step':
                return self._step_environment(request)
            elif action == 'reset':
                return self._reset_environment(request)
            elif action == 'destroy':
                return self._destroy_environment(request)
            elif action == 'list':
                return self._list_environments(request)
            elif action == 'status':
                return self._get_status(request)
            else:
                return {'success': False, 'error': f'Unknown action: {action}'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _create_environment(self, request):
        """Create a new environment from template."""
        template_data = request.get('template', {})
        env_id = request.get('env_id', f'env_{len(self.environments)}')
        
        template = SandboxTemplate(**template_data)
        env = FreeroamTemplateEnv(template=template)
        
        self.environments[env_id] = env
        
        return {
            'success': True,
            'env_id': env_id,
            'template': asdict(template)
        }
    
    def _step_environment(self, request):
        """Step an environment."""
        env_id = request.get('env_id')
        action = request.get('action')
        
        if env_id not in self.environments:
            return {'success': False, 'error': f'Environment {env_id} not found'}
        
        env = self.environments[env_id]
        obs, reward, terminated, truncated, info = env.step(action)
        
        return {
            'success': True,
            'observation': obs,
            'reward': reward,
            'terminated': terminated,
            'truncated': truncated,
            'info': info
        }
    
    def _reset_environment(self, request):
        """Reset an environment."""
        env_id = request.get('env_id')
        
        if env_id not in self.environments:
            return {'success': False, 'error': f'Environment {env_id} not found'}
        
        env = self.environments[env_id]
        obs, info = env.reset()
        
        return {
            'success': True,
            'observation': obs,
            'info': info
        }
    
    def _destroy_environment(self, request):
        """Destroy an environment."""
        env_id = request.get('env_id')
        
        if env_id in self.environments:
            del self.environments[env_id]
            return {'success': True, 'message': f'Environment {env_id} destroyed'}
        else:
            return {'success': False, 'error': f'Environment {env_id} not found'}
    
    def _list_environments(self, request):
        """List all environments."""
        return {
            'success': True,
            'environments': list(self.environments.keys())
        }
    
    def _get_status(self, request):
        """Get server status."""
        return {
            'success': True,
            'status': 'running',
            'environment_count': len(self.environments),
            'environments': list(self.environments.keys())
        }

def main():
    """Main function to run the sandbox server."""
    server = SandboxServer()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down sandbox server...")
        server.stop()

if __name__ == "__main__":
    main()
