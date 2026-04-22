#!/bin/sh
# Recreate config file
rm -rf /usr/share/nginx/html/env-config.js
touch /usr/share/nginx/html/env-config.js

# Add assignment 
echo "window.__RUNTIME_CONFIG__ = {" >> /usr/share/nginx/html/env-config.js

# Read each line in .env file
# Each line represents key=value pairs
if [ -f .env ]; then
  export $(cat .env | xargs)
fi

# Read specific environment variables and add them to the config file
echo "  VITE_API_URL: \"$VITE_API_URL\"," >> /usr/share/nginx/html/env-config.js

echo "};" >> /usr/share/nginx/html/env-config.js
