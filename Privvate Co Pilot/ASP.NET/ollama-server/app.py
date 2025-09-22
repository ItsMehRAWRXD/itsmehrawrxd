import os
import requests
from flask import Flask, request, jsonify, stream_with_context
from flask_cors import CORS
import logging

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
OLLAMA_URL = os.environ.get('OLLAMA_URL', 'http://localhost:11434')
API_KEY = os.environ.get('YOUR_API_KEY', None)
DEFAULT_MODEL = os.environ.get('DEFAULT_MODEL', 'llama3')

@app.before_request
def check_auth():
    """Check API key authentication if configured"""
    if not API_KEY:
        return  # No authentication required
    
    auth_header = request.headers.get('Authorization')
    if not auth_header or auth_header != f'Bearer {API_KEY}':
        return jsonify({'error': 'Unauthorized'}), 401

@app.route('/api/generate', methods=['POST'])
def generate_text():
    """Generate text using Ollama"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        prompt = data.get('prompt', '')
        model = data.get('model', DEFAULT_MODEL)
        stream = data.get('stream', False)
        
        if not prompt:
            return jsonify({'error': 'No prompt provided'}), 400
        
        logger.info(f"Generating text with model: {model}")
        
        # Prepare Ollama request
        ollama_data = {
            'model': model,
            'prompt': prompt,
            'stream': stream
        }
        
        # Add optional parameters
        if 'temperature' in data:
            ollama_data['options'] = {'temperature': data['temperature']}
        if 'max_tokens' in data:
            ollama_data['options'] = ollama_data.get('options', {})
            ollama_data['options']['num_predict'] = data['max_tokens']
        
        if stream:
            return stream_response(ollama_data)
        else:
            return generate_single_response(ollama_data)
            
    except Exception as e:
        logger.error(f"Error in generate_text: {str(e)}")
        return jsonify({'error': str(e)}), 500

def generate_single_response(ollama_data):
    """Generate a single response from Ollama"""
    try:
        response = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json=ollama_data,
            timeout=120
        )
        
        if response.status_code != 200:
            logger.error(f"Ollama API error: {response.status_code} - {response.text}")
            return jsonify({'error': f'Ollama API error: {response.status_code}'}), 500
        
        ollama_response = response.json()
        
        return jsonify({
            'response': ollama_response.get('response', ''),
            'model': ollama_response.get('model', ''),
            'done': ollama_response.get('done', True)
        })
        
    except requests.exceptions.Timeout:
        logger.error("Ollama API timeout")
        return jsonify({'error': 'Request timeout'}), 504
    except requests.exceptions.ConnectionError:
        logger.error("Cannot connect to Ollama")
        return jsonify({'error': 'Cannot connect to Ollama service'}), 503
    except Exception as e:
        logger.error(f"Error calling Ollama: {str(e)}")
        return jsonify({'error': str(e)}), 500

def stream_response(ollama_data):
    """Stream response from Ollama"""
    try:
        response = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json=ollama_data,
            stream=True,
            timeout=120
        )
        
        if response.status_code != 200:
            logger.error(f"Ollama API error: {response.status_code} - {response.text}")
            return jsonify({'error': f'Ollama API error: {response.status_code}'}), 500
        
        def generate():
            try:
                for line in response.iter_lines():
                    if line:
                        line_str = line.decode('utf-8')
                        if line_str.strip():
                            yield f"data: {line_str}\n\n"
            except Exception as e:
                logger.error(f"Error in stream: {str(e)}")
                yield f"data: {jsonify({'error': str(e)})}\n\n"
        
        return app.response_class(
            stream_with_context(generate()),
            mimetype='text/plain'
        )
        
    except requests.exceptions.Timeout:
        logger.error("Ollama API timeout")
        return jsonify({'error': 'Request timeout'}), 504
    except requests.exceptions.ConnectionError:
        logger.error("Cannot connect to Ollama")
        return jsonify({'error': 'Cannot connect to Ollama service'}), 503
    except Exception as e:
        logger.error(f"Error calling Ollama: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/models', methods=['GET'])
def list_models():
    """List available Ollama models"""
    try:
        response = requests.get(f"{OLLAMA_URL}/api/tags", timeout=30)
        
        if response.status_code != 200:
            return jsonify({'error': f'Ollama API error: {response.status_code}'}), 500
        
        ollama_data = response.json()
        models = []
        
        for model in ollama_data.get('models', []):
            models.append({
                'name': model.get('name', ''),
                'size': model.get('size', 0),
                'modified_at': model.get('modified_at', ''),
                'family': model.get('details', {}).get('family', ''),
                'format': model.get('details', {}).get('format', '')
            })
        
        return jsonify({'models': models})
        
    except Exception as e:
        logger.error(f"Error listing models: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        response = requests.get(f"{OLLAMA_URL}/api/tags", timeout=10)
        if response.status_code == 200:
            return jsonify({
                'status': 'healthy',
                'ollama_url': OLLAMA_URL,
                'auth_required': API_KEY is not None
            })
        else:
            return jsonify({
                'status': 'unhealthy',
                'ollama_url': OLLAMA_URL,
                'error': f'Ollama returned {response.status_code}'
            }), 503
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'ollama_url': OLLAMA_URL,
            'error': str(e)
        }), 503

@app.route('/', methods=['GET'])
def index():
    """Root endpoint with API information"""
    return jsonify({
        'service': 'Ollama API Proxy',
        'version': '1.0.0',
        'endpoints': {
            'POST /api/generate': 'Generate text using Ollama',
            'GET /api/models': 'List available models',
            'GET /api/health': 'Health check'
        },
        'ollama_url': OLLAMA_URL,
        'auth_required': API_KEY is not None
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    logger.info(f"Starting Ollama API Proxy on port {port}")
    logger.info(f"Ollama URL: {OLLAMA_URL}")
    logger.info(f"Default model: {DEFAULT_MODEL}")
    logger.info(f"Authentication: {'Required' if API_KEY else 'Disabled'}")
    
    app.run(host='0.0.0.0', port=port, debug=debug)
