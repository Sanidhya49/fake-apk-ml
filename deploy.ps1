# Flask APK Detection API Deployment Script (PowerShell)
# This script provides easy commands to build and run the Flask backend on Windows

param(
    [string]$Command = "help",
    [string]$Mode = "dev"
)

# Configuration
$IMAGE_NAME = "fake-apk-flask"
$CONTAINER_NAME = "fake-apk-flask-api"
$PORT = 9000

function Write-Header {
    Write-Host ""
    Write-Host "==========================================" -ForegroundColor Blue
    Write-Host "    Fake APK Detection Flask API" -ForegroundColor Blue
    Write-Host "==========================================" -ForegroundColor Blue
    Write-Host ""
}

function Write-Success {
    param([string]$Message)
    Write-Host "✅ $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "❌ $Message" -ForegroundColor Red
}

function Write-Info {
    param([string]$Message)
    Write-Host "ℹ️  $Message" -ForegroundColor Blue
}

function Write-Warning {
    param([string]$Message)
    Write-Host "⚠️  $Message" -ForegroundColor Yellow
}

function Test-Docker {
    try {
        $null = docker --version
        $null = docker info 2>$null
        Write-Success "Docker is available and running"
        return $true
    }
    catch {
        Write-Error "Docker is not installed or not running"
        return $false
    }
}

function Test-Requirements {
    if (-not (Test-Path "requirements.txt") -or -not (Test-Path "flask_requirements.txt")) {
        Write-Error "Requirements files not found. Make sure you're in the project root directory."
        return $false
    }

    if (-not (Test-Path "flask_app\main.py")) {
        Write-Error "Flask app not found. Make sure flask_app\main.py exists."
        return $false
    }

    if (-not (Test-Path "models")) {
        Write-Warning "Models directory not found. Creating it..."
        New-Item -ItemType Directory -Path "models" -Force | Out-Null
    }

    Write-Success "Requirements check passed"
    return $true
}

function Build-Image {
    param([string]$BuildMode = "dev")
    
    Write-Info "Building Docker image..."
    
    if ($BuildMode -eq "prod") {
        Write-Info "Building production image with Gunicorn..."
        docker build -f Dockerfile.flask.prod -t "${IMAGE_NAME}:prod" .
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Production image built successfully"
        } else {
            Write-Error "Failed to build production image"
            return $false
        }
    } else {
        Write-Info "Building development image..."
        docker build -t "${IMAGE_NAME}:dev" .
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Development image built successfully"
        } else {
            Write-Error "Failed to build development image"
            return $false
        }
    }
    return $true
}

function Start-Development {
    Write-Info "Starting Flask development server..."
    
    # Stop existing container if running
    docker stop "$CONTAINER_NAME-dev" 2>$null | Out-Null
    docker rm "$CONTAINER_NAME-dev" 2>$null | Out-Null
    
    # Get current directory for volume mounting
    $currentDir = (Get-Location).Path
    
    # Run development container
    docker run -d `
        --name "$CONTAINER_NAME-dev" `
        -p "${PORT}:${PORT}" `
        -v "${currentDir}\artifacts:/app/artifacts" `
        -v "${currentDir}\models:/app/models" `
        -v "${currentDir}:/app" `
        -e FLASK_DEBUG=true `
        -e FLASK_ENV=development `
        --env-file .env `
        "${IMAGE_NAME}:dev"
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Development server started on port $PORT"
        Write-Info "Container name: $CONTAINER_NAME-dev"
        Write-Info "API URL: http://localhost:$PORT"
        return $true
    } else {
        Write-Error "Failed to start development server"
        return $false
    }
}

function Start-Production {
    Write-Info "Starting Flask production server with Gunicorn..."
    
    # Stop existing container if running
    docker stop "$CONTAINER_NAME-prod" 2>$null | Out-Null
    docker rm "$CONTAINER_NAME-prod" 2>$null | Out-Null
    
    # Get current directory for volume mounting
    $currentDir = (Get-Location).Path
    
    # Ensure logs directory exists
    if (-not (Test-Path "logs")) {
        New-Item -ItemType Directory -Path "logs" -Force | Out-Null
    }
    
    # Run production container
    docker run -d `
        --name "$CONTAINER_NAME-prod" `
        -p "${PORT}:${PORT}" `
        -v "${currentDir}\artifacts:/app/artifacts" `
        -v "${currentDir}\models:/app/models" `
        -v "${currentDir}\logs:/app/logs" `
        -e FLASK_ENV=production `
        -e FLASK_DEBUG=false `
        --env-file .env `
        --restart unless-stopped `
        "${IMAGE_NAME}:prod"
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Production server started on port $PORT"
        Write-Info "Container name: $CONTAINER_NAME-prod"
        Write-Info "API URL: http://localhost:$PORT"
        return $true
    } else {
        Write-Error "Failed to start production server"
        return $false
    }
}

function Start-DockerCompose {
    param([string]$ComposeMode = "")
    
    if ($ComposeMode -eq "prod") {
        Write-Info "Starting production stack with docker-compose..."
        docker-compose -f docker-compose.prod.yml up -d
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Production stack started"
        }
    } elseif ($ComposeMode -eq "dev") {
        Write-Info "Starting development stack with docker-compose..."
        docker-compose -f docker-compose.dev.yml up -d
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Development stack started"
        }
    } else {
        Write-Info "Starting default stack with docker-compose..."
        docker-compose up -d flask-ml
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Flask service started"
        }
    }
}

function Stop-Services {
    Write-Info "Stopping Flask services..."
    
    # Stop standalone containers
    docker stop "$CONTAINER_NAME-dev" "$CONTAINER_NAME-prod" 2>$null | Out-Null
    docker rm "$CONTAINER_NAME-dev" "$CONTAINER_NAME-prod" 2>$null | Out-Null
    
    # Stop docker-compose services
    docker-compose -f docker-compose.yml down 2>$null | Out-Null
    docker-compose -f docker-compose.dev.yml down 2>$null | Out-Null
    docker-compose -f docker-compose.prod.yml down 2>$null | Out-Null
    
    Write-Success "All Flask services stopped"
}

function Show-Logs {
    param([string]$Service)
    
    switch ($Service) {
        "dev" {
            docker logs -f "$CONTAINER_NAME-dev"
        }
        "prod" {
            docker logs -f "$CONTAINER_NAME-prod"
        }
        "compose" {
            docker-compose logs -f flask-ml
        }
        default {
            Write-Warning "Specify service: dev, prod, or compose"
        }
    }
}

function Test-Api {
    Write-Info "Testing Flask API..."
    
    # Wait for service to be ready
    Start-Sleep -Seconds 5
    
    try {
        $response = Invoke-RestMethod -Uri "http://localhost:$PORT/" -Method Get -TimeoutSec 10
        Write-Success "API is responding successfully"
        $response | ConvertTo-Json -Depth 3
        return $true
    }
    catch {
        Write-Error "API is not responding on port $PORT"
        Write-Info "Check logs with: .\deploy.ps1 logs [dev|prod|compose]"
        return $false
    }
}

function Show-Status {
    Write-Info "Service Status:"
    
    # Check standalone containers
    $containers = docker ps --filter "name=$CONTAINER_NAME" --format "table {{.Names}}`t{{.Status}}`t{{.Ports}}"
    if ($containers -match $CONTAINER_NAME) {
        Write-Success "Standalone containers:"
        docker ps --filter "name=$CONTAINER_NAME" --format "table {{.Names}}`t{{.Status}}`t{{.Ports}}"
    }
    
    # Check docker-compose services
    try {
        $composeServices = docker-compose ps 2>$null
        if ($composeServices -match "flask") {
            Write-Success "Docker-compose services:"
            docker-compose ps
        }
    }
    catch {
        # Ignore compose errors if not using compose
    }
    
    # Test API availability
    Write-Host ""
    Test-Api | Out-Null
}

function Remove-All {
    Write-Info "Cleaning up Docker resources..."
    
    # Stop and remove containers
    Stop-Services
    
    # Remove images
    docker rmi "${IMAGE_NAME}:dev" "${IMAGE_NAME}:prod" 2>$null | Out-Null
    
    # Remove unused volumes and networks
    docker volume prune -f | Out-Null
    docker network prune -f | Out-Null
    
    Write-Success "Cleanup completed"
}

function Show-Help {
    Write-Header
    Write-Host "Usage: .\deploy.ps1 -Command [COMMAND] -Mode [MODE]"
    Write-Host ""
    Write-Host "Commands:" -ForegroundColor Yellow
    Write-Host "  build                Build Docker image (Mode: dev|prod, default: dev)"
    Write-Host "  run                  Run standalone container (Mode: dev|prod, default: dev)"
    Write-Host "  compose              Run with docker-compose (Mode: dev|prod)"
    Write-Host "  stop                 Stop all Flask services"
    Write-Host "  logs                 Show service logs (Mode: dev|prod|compose)"
    Write-Host "  test                 Test API endpoints"
    Write-Host "  status               Show service status"
    Write-Host "  cleanup              Clean up all Docker resources"
    Write-Host "  help                 Show this help message"
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor Yellow
    Write-Host "  .\deploy.ps1 -Command build -Mode dev      # Build development image"
    Write-Host "  .\deploy.ps1 -Command run -Mode prod       # Run production container"
    Write-Host "  .\deploy.ps1 -Command compose -Mode dev    # Start with docker-compose (dev)"
    Write-Host "  .\deploy.ps1 -Command logs -Mode prod      # Show production logs"
    Write-Host "  .\deploy.ps1 -Command test                 # Test API"
    Write-Host ""
    Write-Host "Environment:" -ForegroundColor Yellow
    Write-Host "  PORT: $PORT"
    Write-Host "  IMAGE: $IMAGE_NAME"
    Write-Host "  CONTAINER: $CONTAINER_NAME"
}

# Main script logic
switch ($Command.ToLower()) {
    "build" {
        Write-Header
        if (-not (Test-Docker)) { exit 1 }
        if (-not (Test-Requirements)) { exit 1 }
        if (-not (Build-Image $Mode)) { exit 1 }
    }
    "run" {
        Write-Header
        if (-not (Test-Docker)) { exit 1 }
        if (-not (Test-Requirements)) { exit 1 }
        if (-not (Build-Image $Mode)) { exit 1 }
        
        if ($Mode -eq "prod") {
            if (-not (Start-Production)) { exit 1 }
        } else {
            if (-not (Start-Development)) { exit 1 }
        }
        
        Start-Sleep -Seconds 5
        Test-Api | Out-Null
    }
    "compose" {
        Write-Header
        if (-not (Test-Docker)) { exit 1 }
        if (-not (Test-Requirements)) { exit 1 }
        Start-DockerCompose $Mode
        Start-Sleep -Seconds 10
        Test-Api | Out-Null
    }
    "stop" {
        Write-Header
        Stop-Services
    }
    "logs" {
        Show-Logs $Mode
    }
    "test" {
        Test-Api | Out-Null
    }
    "status" {
        Show-Status
    }
    "cleanup" {
        Write-Header
        Remove-All
    }
    default {
        Show-Help
    }
}
