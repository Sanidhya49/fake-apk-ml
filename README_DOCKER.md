# Docker Deployment Guide for Flask APK Detection API

## Quick Start Commands

### 🚀 Development Mode (Recommended for testing)

**Windows PowerShell:**
```powershell
.\deploy.ps1 -Command run -Mode dev
```

**Linux/Mac Bash:**
```bash
chmod +x deploy.sh
./deploy.sh run dev
```

**Manual Docker Commands:**
```bash
# Build development image
docker build -t fake-apk-flask:dev .

# Run development container
docker run -d \
  --name fake-apk-flask-api-dev \
  -p 9000:9000 \
  -v "$(pwd)/artifacts:/app/artifacts" \
  -v "$(pwd)/models:/app/models" \
  -v "$(pwd):/app" \
  -e FLASK_DEBUG=true \
  --env-file .env \
  fake-apk-flask:dev

# Test the API
curl http://localhost:9000/
```

### 🏭 Production Mode

**Windows PowerShell:**
```powershell
.\deploy.ps1 -Command run -Mode prod
```

**Linux/Mac Bash:**
```bash
./deploy.sh run prod
```

**Manual Docker Commands:**
```bash
# Build production image
docker build -f Dockerfile.flask.prod -t fake-apk-flask:prod .

# Run production container
docker run -d \
  --name fake-apk-flask-api-prod \
  -p 9000:9000 \
  -v "$(pwd)/artifacts:/app/artifacts" \
  -v "$(pwd)/models:/app/models" \
  -v "$(pwd)/logs:/app/logs" \
  -e FLASK_ENV=production \
  --env-file .env \
  --restart unless-stopped \
  fake-apk-flask:prod
```

### 🐳 Docker Compose

**Development Stack:**
```bash
docker-compose -f docker-compose.dev.yml up -d
```

**Production Stack:**
```bash
docker-compose -f docker-compose.prod.yml up -d
```

**Standard Stack:**
```bash
docker-compose up -d flask-ml
```

## Available Docker Files

| File | Purpose | Server | Use Case |
|------|---------|--------|----------|
| `Dockerfile` | Development | Flask dev server | Local development, debugging |
| `Dockerfile.flask.prod` | Production | Gunicorn | Production deployment |
| `docker-compose.yml` | Multi-service | Mixed | FastAPI + Streamlit + Flask |
| `docker-compose.dev.yml` | Development | Flask dev | Development with hot reload |
| `docker-compose.prod.yml` | Production | Gunicorn + Nginx | Full production stack |

## API Endpoints

Once running, the API provides these endpoints:

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/` | Health check |
| POST | `/scan` | Single APK analysis |
| POST | `/scan-batch` | Batch APK analysis |
| POST | `/report` | HTML report generation |

**Test the API:**
```bash
# Health check
curl http://localhost:9000/

# Upload and scan APK (replace with actual APK file)
curl -X POST -F "file=@sample.apk" http://localhost:9000/scan
```

## Environment Configuration

Key environment variables in `.env`:

```properties
# Flask Configuration
FLASK_HOST=0.0.0.0
FLASK_PORT=9000
FLASK_DEBUG=false
FLASK_ENV=production

# ML Configuration  
ML_FAKE_THRESHOLD=0.3000
ML_AGGRESSIVE=0
ML_OFFICIAL_OVERRIDE=1

# Service URLs
ML_SERVICE_URL=http://localhost:9000
```

## Volume Mounts

The containers use these volume mounts:

- `./artifacts:/app/artifacts` - Cached analysis results
- `./models:/app/models` - ML model files (required)
- `./logs:/app/logs` - Application logs (production only)
- `.:/app` - Source code (development only)

## Common Commands

### View Logs
```bash
# Development container
docker logs -f fake-apk-flask-api-dev

# Production container  
docker logs -f fake-apk-flask-api-prod

# Docker Compose
docker-compose logs -f flask-ml
```

### Stop Services
```bash
# Stop and remove containers
docker stop fake-apk-flask-api-dev fake-apk-flask-api-prod
docker rm fake-apk-flask-api-dev fake-apk-flask-api-prod

# Stop docker-compose services
docker-compose down
```

### Container Status
```bash
# List running containers
docker ps --filter name=fake-apk

# Check container health
docker inspect fake-apk-flask-api-prod | grep -A 10 Health
```

## Troubleshooting

### 1. Container Won't Start
```bash
# Check container logs
docker logs fake-apk-flask-api-dev

# Check if port is already in use
netstat -tulpn | grep 9000  # Linux
netstat -ano | findstr 9000  # Windows
```

### 2. API Not Responding
```bash
# Test container network
docker exec fake-apk-flask-api-dev curl localhost:9000

# Check if service is running inside container
docker exec fake-apk-flask-api-dev ps aux | grep python
```

### 3. Model Loading Issues
```bash
# Check if models directory is mounted
docker exec fake-apk-flask-api-dev ls -la models/

# Verify model file exists
docker exec fake-apk-flask-api-dev ls -la models/xgb_model.joblib
```

### 4. Permission Issues (Linux/Mac)
```bash
# Fix volume permissions
sudo chown -R $USER:$USER ./artifacts ./logs

# Run with user mapping
docker run --user $(id -u):$(id -g) ...
```

## Production Considerations

### Security
- Use specific user instead of root (production Dockerfile includes this)
- Configure proper CORS origins instead of allowing all
- Add authentication and rate limiting as needed
- Use HTTPS with SSL certificates

### Performance
- Use Gunicorn with multiple workers (production setup)
- Configure appropriate CPU and memory limits
- Set up monitoring and logging
- Use nginx reverse proxy for static files

### Scaling
- Use Docker Swarm or Kubernetes for orchestration
- Set up load balancing for multiple instances
- Configure persistent storage for artifacts and logs
- Implement health checks and auto-restart

## Integration with Frontend

The React frontend should connect to the Flask API:

**Frontend .env:**
```properties
VITE_API_BASE_URL=http://localhost:9000
```

**API Service Usage:**
```javascript
import { APKAnalysisService } from './services/api';

// Single file analysis
const result = await APKAnalysisService.scanSingle(file);

// Batch analysis
const results = await APKAnalysisService.scanBatch(files);

// Generate report
const report = await APKAnalysisService.generateReport(file);
```

## Next Steps

1. **Start the Flask API**: Use the commands above
2. **Test the endpoints**: Use curl or the provided test scripts
3. **Start your React frontend**: Connect to the Flask API
4. **Deploy to production**: Use the production Docker setup
5. **Monitor and scale**: Set up proper logging and monitoring

The Flask API is now ready to handle APK analysis requests from your React frontend!
