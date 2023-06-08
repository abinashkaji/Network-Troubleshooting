# Use the official Python base image
FROM python:3.7

# Set the working directory inside the container
WORKDIR /LMS

# Copy the requirements.txt file to the container
COPY requirements.txt .

# Install the Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the Django project code to the container
COPY . .

# Expose the port on which the Django app will run (default is 8000)
EXPOSE 8000

# Set environment variables if needed
# ENV DJANGO_SETTINGS_MODULE=myproject.settings.production

# Run the Django development server
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]

