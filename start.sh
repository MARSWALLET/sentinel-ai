#!/bin/bash
# ============================================
# SentinelAI - Start Script
# ============================================
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "  ____            _   _ _       _       ___    ____"
echo " / ___|  ___  ___| |_(_) | __ _| |     |_ _|  / ___|"
echo " \\___ \\ / _ \\/ __| __| | |/ _\` | |      | |  | |    "
echo "  ___) |  __/\\__ \\ |_| | | (_| | | ___  | |  | |___ "
echo " |____/ \\___||___/\\__|_|_|\\__,_|_|( ) |___|  \\____|"
echo "                                    |/               "
echo -e "${NC}"
echo "  AI-Powered Security Scanning Agent"
echo "  ==================================="
echo ""

# Check if .env exists
if [ ! -f .env ]; then
    echo -e "${YELLOW}⚠ .env file not found. Creating from .env.example...${NC}"
    cp .env.example .env
    echo -e "${RED}✗ Please edit .env and set your API keys before continuing.${NC}"
    exit 1
fi

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}✗ Docker is not installed. Please install Docker first.${NC}"
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo -e "${RED}✗ Docker Compose is not installed. Please install Docker Compose first.${NC}"
    exit 1
fi

# Determine docker compose command
if docker compose version &> /dev/null; then
    COMPOSE_CMD="docker compose"
else
    COMPOSE_CMD="docker-compose"
fi

# Function to check if containers are running
is_running() {
    $COMPOSE_CMD ps | grep -q "Up"
}

case "${1:-up}" in
    up)
        echo -e "${BLUE}🚀 Starting SentinelAI services...${NC}"
        $COMPOSE_CMD pull
        $COMPOSE_CMD up -d --build
        echo ""
        echo -e "${GREEN}✓ SentinelAI is starting up!${NC}"
        echo ""
        echo -e "  ${BLUE}API Documentation:${NC}  http://localhost:8000/docs"
        echo -e "  ${BLUE}API Health Check:${NC}   http://localhost:8000/api/health"
        echo -e "  ${BLUE}Flower Dashboard:${NC}  http://localhost:5555"
        echo -e "  ${BLUE}ZAP Proxy:${NC}         http://localhost:8090"
        echo ""
        echo -e "  ${YELLOW}Run './start.sh logs' to view logs${NC}"
        ;;

    down)
        echo -e "${BLUE}🛑 Stopping SentinelAI services...${NC}"
        $COMPOSE_CMD down
        echo -e "${GREEN}✓ Services stopped.${NC}"
        ;;

    restart)
        echo -e "${BLUE}🔄 Restarting SentinelAI services...${NC}"
        $COMPOSE_CMD restart
        echo -e "${GREEN}✓ Services restarted.${NC}"
        ;;

    logs)
        echo -e "${BLUE}📋 Viewing logs...${NC}"
        $COMPOSE_CMD logs -f --tail=100
        ;;

    logs-api)
        echo -e "${BLUE}📋 Viewing API logs...${NC}"
        $COMPOSE_CMD logs -f --tail=100 api
        ;;

    logs-worker)
        echo -e "${BLUE}📋 Viewing Worker logs...${NC}"
        $COMPOSE_CMD logs -f --tail=100 worker
        ;;

    scale)
        WORKER_COUNT=${2:-3}
        echo -e "${BLUE}📈 Scaling workers to ${WORKER_COUNT}...${NC}"
        $COMPOSE_CMD up -d --scale worker=${WORKER_COUNT}
        echo -e "${GREEN}✓ Scaled to ${WORKER_COUNT} workers.${NC}"
        ;;

    status)
        echo -e "${BLUE}📊 Service Status:${NC}"
        $COMPOSE_CMD ps
        ;;

    update)
        echo -e "${BLUE}⬇ Pulling latest images...${NC}"
        $COMPOSE_CMD pull
        echo -e "${BLUE}🔄 Restarting services...${NC}"
        $COMPOSE_CMD up -d
        echo -e "${GREEN}✓ Updated and restarted.${NC}"
        ;;

    clean)
        echo -e "${YELLOW}⚠ This will remove all data including scan history and reports.${NC}"
        read -p "Are you sure? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            $COMPOSE_CMD down -v
            echo -e "${GREEN}✓ All data removed.${NC}"
        else
            echo -e "${BLUE}Cancelled.${NC}"
        fi
        ;;

    *)
        echo "Usage: ./start.sh [up|down|restart|logs|logs-api|logs-worker|scale|status|update|clean]"
        echo ""
        echo "Commands:"
        echo "  up           - Start all services (default)"
        echo "  down         - Stop all services"
        echo "  restart      - Restart all services"
        echo "  logs         - View all logs"
        echo "  logs-api     - View API logs"
        echo "  logs-worker  - View worker logs"
        echo "  scale <n>    - Scale workers (default: 3)"
        echo "  status       - Show service status"
        echo "  update       - Pull latest images and restart"
        echo "  clean        - Remove all data (WARNING: destructive)"
        ;;
esac