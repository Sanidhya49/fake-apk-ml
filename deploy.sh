#!/bin/bash

# Flask APK Detection API Deployment Script
# This script provides easy commands to build and run the Flask backend

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
IMAGE_NAME="fake-apk-flask"
CONTAINER_NAME="fake-apk-flask-api"
PORT=9000

print_header() {
    echo -e "${BLUE}"
    echo "=========================================="
    echo "    Fake APK Detection Flask API"
    echo "=========================================="
    echo -e "${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed or not in PATH"
        exit 1
    fi

    if ! docker info &> /dev/null; then
        print_error "Docker daemon is not running"
        exit 1
    fi

    print_success "Docker is available and running"
}

check_requirements() {
    if [ ! -f "requirements.txt" ] || [ ! -f "flask_requirements.txt" ]; then
        print_error "Requirements files not found. Make sure you're in the project root directory."
        exit 1
    fi

    if [ ! -f "flask_app/main.py" ]; then
        print_error "Flask app not found. Make sure flask_app/main.py exists."
        exit 1
    fi

    if [ ! -d "models" ]; then
        print_warning "Models directory not found. Creating it..."
        mkdir -p models
    fi

    print_success "Requirements check passed"
}

build_image() {
    print_info "Building Docker image..."
    
    if [ "$1" = "prod" ]; then
        print_info "Building production image with Gunicorn..."
        docker build -f Dockerfile.flask.prod -t ${IMAGE_NAME}:prod .
        print_success "Production image built successfully"
    else
        print_info "Building development image..."
        docker build -t ${IMAGE_NAME}:dev .
        print_success "Development image built successfully"
    fi
}

run_development() {
    print_info "Starting Flask development server..."
    
    # Stop existing container if running
    docker stop ${CONTAINER_NAME}-dev 2>/dev/null || true
    docker rm ${CONTAINER_NAME}-dev 2>/dev/null || true
    
    # Run development container
    docker run -d \
        --name ${CONTAINER_NAME}-dev \
        -p ${PORT}:${PORT} \
        -v "$(pwd)/artifacts:/app/artifacts" \
        -v "$(pwd)/models:/app/models" \
        -v "$(pwd):/app" \
        -e FLASK_DEBUG=true \
        -e FLASK_ENV=development \
        --env-file .env \
        ${IMAGE_NAME}:dev
    
    print_success "Development server started on port ${PORT}"
    print_info "Container name: ${CONTAINER_NAME}-dev"
    print_info "API URL: http://localhost:${PORT}"
}

run_production() {
    print_info "Starting Flask production server with Gunicorn..."
    
    # Stop existing container if running
    docker stop ${CONTAINER_NAME}-prod 2>/dev/null || true
    docker rm ${CONTAINER_NAME}-prod 2>/dev/null || true
    
    # Run production container
    docker run -d \
        --name ${CONTAINER_NAME}-prod \
        -p ${PORT}:${PORT} \
        -v "$(pwd)/artifacts:/app/artifacts" \
        -v "$(pwd)/models:/app/models" \
        -v "$(pwd)/logs:/app/logs" \
        -e FLASK_ENV=production \
        -e FLASK_DEBUG=false \
        --env-file .env \
        --restart unless-stopped \
        ${IMAGE_NAME}:prod
    
    print_success "Production server started on port ${PORT}"
    print_info "Container name: ${CONTAINER_NAME}-prod"
    print_info "API URL: http://localhost:${PORT}"
}

run_docker_compose() {
    local mode=$1
    
    if [ "$mode" = "prod" ]; then
        print_info "Starting production stack with docker-compose..."
        docker-compose -f docker-compose.prod.yml up -d
        print_success "Production stack started"
    elif [ "$mode" = "dev" ]; then
        print_info "Starting development stack with docker-compose..."
        docker-compose -f docker-compose.dev.yml up -d
        print_success "Development stack started"
    else
        print_info "Starting default stack with docker-compose..."
        docker-compose up -d flask-ml
        print_success "Flask service started"
    fi
}

stop_services() {
    print_info "Stopping Flask services..."
    
    # Stop standalone containers
    docker stop ${CONTAINER_NAME}-dev ${CONTAINER_NAME}-prod 2>/dev/null || true
    docker rm ${CONTAINER_NAME}-dev ${CONTAINER_NAME}-prod 2>/dev/null || true
    
    # Stop docker-compose services
    docker-compose -f docker-compose.yml down 2>/dev/null || true
    docker-compose -f docker-compose.dev.yml down 2>/dev/null || true
    docker-compose -f docker-compose.prod.yml down 2>/dev/null || true
    
    print_success "All Flask services stopped"
}

show_logs() {
    local service=$1
    
    if [ "$service" = "dev" ]; then
        docker logs -f ${CONTAINER_NAME}-dev
    elif [ "$service" = "prod" ]; then
        docker logs -f ${CONTAINER_NAME}-prod
    elif [ "$service" = "compose" ]; then
        docker-compose logs -f flask-ml
    else
        print_warning "Specify service: dev, prod, or compose"
    fi
}

test_api() {
    print_info "Testing Flask API..."
    
    # Wait for service to be ready
    sleep 5
    
    if curl -f http://localhost:${PORT}/ > /dev/null 2>&1; then
        print_success "API is responding successfully"
        curl -s http://localhost:${PORT}/ | jq . 2>/dev/null || curl -s http://localhost:${PORT}/
    else
        print_error "API is not responding on port ${PORT}"
        print_info "Check logs with: $0 logs [dev|prod|compose]"
        return 1
    fi
}

show_status() {
    print_info "Service Status:"
    
    # Check standalone containers
    if docker ps --filter name=${CONTAINER_NAME} --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -q ${CONTAINER_NAME}; then
        print_success "Standalone containers:"
        docker ps --filter name=${CONTAINER_NAME} --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
    fi
    
    # Check docker-compose services
    if docker-compose ps 2>/dev/null | grep -q flask; then
        print_success "Docker-compose services:"
        docker-compose ps
    fi
    
    # Test API availability
    echo
    test_api
}

cleanup() {
    print_info "Cleaning up Docker resources..."
    
    # Stop and remove containers
    stop_services
    
    # Remove images
    docker rmi ${IMAGE_NAME}:dev ${IMAGE_NAME}:prod 2>/dev/null || true
    
    # Remove unused volumes and networks
    docker volume prune -f
    docker network prune -f
    
    print_success "Cleanup completed"
}

show_help() {
    print_header
    echo "Usage: $0 [COMMAND]"
    echo
    echo "Commands:"
    echo "  build [dev|prod]     Build Docker image (default: dev)"
    echo "  run [dev|prod]       Run standalone container (default: dev)"
    echo "  compose [dev|prod]   Run with docker-compose (default: standard)"
    echo "  stop                 Stop all Flask services"
    echo "  logs [dev|prod|compose] Show service logs"
    echo "  test                 Test API endpoints"
    echo "  status               Show service status"
    echo "  cleanup              Clean up all Docker resources"
    echo "  help                 Show this help message"
    echo
    echo "Examples:"
    echo "  $0 build dev         # Build development image"
    echo "  $0 run prod          # Run production container"
    echo "  $0 compose dev       # Start with docker-compose (dev)"
    echo "  $0 logs prod         # Show production logs"
    echo "  $0 test              # Test API"
    echo
    echo "Environment:"
    echo "  PORT: ${PORT}"
    echo "  IMAGE: ${IMAGE_NAME}"
    echo "  CONTAINER: ${CONTAINER_NAME}"
}

# Main script logic
main() {
    case "${1:-help}" in
        "build")
            print_header
            check_docker
            check_requirements
            build_image $2
            ;;
        "run")
            print_header
            check_docker
            check_requirements
            build_image $2
            if [ "$2" = "prod" ]; then
                run_production
            else
                run_development
            fi
            sleep 5
            test_api
            ;;
        "compose")
            print_header
            check_docker
            check_requirements
            run_docker_compose $2
            sleep 10
            test_api
            ;;
        "stop")
            print_header
            stop_services
            ;;
        "logs")
            show_logs $2
            ;;
        "test")
            test_api
            ;;
        "status")
            show_status
            ;;
        "cleanup")
            print_header
            cleanup
            ;;
        "help"|*)
            show_help
            ;;
    esac
}

# Run main function with all arguments
main "$@"
