FROM node:20-alpine

WORKDIR /app

# Copy package files and source code
COPY package*.json ./
COPY . .

# Install dependencies and build
RUN npm install && npm run build

# Expose port 3005
EXPOSE 3005

# Start the application
CMD ["npm", "run", "start:prod"] 