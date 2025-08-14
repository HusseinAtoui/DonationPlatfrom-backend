# Use a small Node.js base image
FROM node:18-alpine

# Set working directory in the container
WORKDIR /app

# Copy only package files first (for better caching)
COPY package*.json ./

# Install only production dependencies
RUN npm install --production

# Copy the rest of your application files
COPY . .

# Expose the port your app runs on
EXPOSE 3000

# Start the app
CMD ["node", "server.js"]
