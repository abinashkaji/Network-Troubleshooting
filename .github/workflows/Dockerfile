# Use an official Python runtime as the base image
FROM python:3.7

# Set the working directory in the container
WORKDIR /LMS

# Copy the requirements file into the container
COPY requirements.txt .

# Install the Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the Django project code into the container
COPY . .

# Set environment variables, if necessary
# ENV DJANGO_SETTINGS_MODULE=myproject.settings.prod

# Run any necessary Django management commands
# RUN python manage.py collectstatic --noinput

# Expose the application's port (change it if necessary)
EXPOSE 8000

# Define the command to run your application
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
