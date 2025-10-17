import logging
import shlex
import subprocess
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.views.generic import View
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from .utility import get_free_port
from .models import Challenge, UserChallenge

# Configure logging
logger = logging.getLogger(__name__)


class ChallengeView(LoginRequiredMixin, View):
    """Handles Docker container management for security challenges."""
    
    login_url = 'login'
    def get(self, request, challenge):
        """Display challenge page for authenticated users."""
        try:
            chal = Challenge.objects.get(name=challenge)
        except ObjectDoesNotExist:
            logger.warning(f"Challenge not found: {challenge}")
            return render(request, 'chal-not-found.html')

        try:
            user_chal = UserChallenge.objects.get(user=request.user, challenge=chal)
            context = {'chal': chal, 'user_chal': user_chal}
        except ObjectDoesNotExist:
            context = {'chal': chal, 'user_chal': None}
            
        return render(request, 'challenge.html', context)
    
    def post(self, request, challenge):
        """Start a Docker container for the challenge."""
        try:
            chal = Challenge.objects.get(name=challenge)
        except ObjectDoesNotExist:
            logger.warning(f"Challenge not found: {challenge}")
            return JsonResponse({
                'message': 'Challenge not found', 
                'status': '404', 
                'endpoint': None
            }, status=404)

        # Check if user already has a running container
        try:
            user_chal = UserChallenge.objects.get(user=request.user, challenge=chal)
            if user_chal.is_live:
                return JsonResponse({
                    'message': 'Container already running',
                    'status': '200',
                    'endpoint': f'http://localhost:{user_chal.port}'
                })
            user_challenge_exists = True
        except ObjectDoesNotExist:
            user_challenge_exists = False

        # Get a free port
        port = get_free_port(chal.start_port, chal.end_port)
        if port is None:
            logger.error(f"No available ports in range {chal.start_port}-{chal.end_port}")
            return JsonResponse({
                'message': 'No available ports',
                'status': '500',
                'endpoint': None
            }, status=500)
        
        # Safely construct and execute Docker command
        container_id = self._start_docker_container(chal, port)
        if not container_id:
            return JsonResponse({
                'message': 'Failed to start container',
                'status': '500',
                'endpoint': None
            }, status=500)
        
        # Update or create UserChallenge record
        try:
            with transaction.atomic():
                if user_challenge_exists:
                    user_chal.container_id = container_id
                    user_chal.port = port
                    user_chal.is_live = True
                    user_chal.save()
                else:
                    user_chal = UserChallenge.objects.create(
                        user=request.user,
                        challenge=chal,
                        container_id=container_id,
                        port=port,
                        is_live=True
                    )
        except Exception as e:
            logger.error(f"Database error: {e}")
            # Clean up container if database operation fails
            self._stop_docker_container(container_id)
            return JsonResponse({
                'message': 'Database error',
                'status': '500',
                'endpoint': None
            }, status=500)
        
        return JsonResponse({
            'message': 'Container started successfully',
            'status': '200',
            'endpoint': f'http://localhost:{port}'
        })



    def delete(self, request, challenge):
        """Stop a Docker container for the challenge."""
        try:
            chal = Challenge.objects.get(name=challenge)
            user_chal = UserChallenge.objects.get(user=request.user, challenge=chal)
        except ObjectDoesNotExist:
            logger.warning(f"Challenge or UserChallenge not found: {challenge}")
            return JsonResponse({
                'message': 'Challenge not found',
                'status': '404'
            }, status=404)

        # Stop the container
        if user_chal.container_id and self._stop_docker_container(user_chal.container_id):
            user_chal.is_live = False
            user_chal.save()
            return JsonResponse({
                'message': 'Container stopped successfully',
                'status': '200'
            })
        else:
            return JsonResponse({
                'message': 'Failed to stop container',
                'status': '500'
            }, status=500)
    
    def put(self, request, challenge):
        """Handle flag submission for challenge completion."""
        # TODO: Implement flag checking functionality
        return JsonResponse({
            'message': 'Flag checking not implemented yet',
            'status': '501'
        }, status=501)
    
    def _start_docker_container(self, challenge, port):
        """Safely start a Docker container and return container ID."""
        try:
            # Validate inputs to prevent injection
            if not self._validate_docker_inputs(challenge.docker_image, challenge.docker_port, port):
                logger.error(f"Invalid Docker inputs: image={challenge.docker_image}, docker_port={challenge.docker_port}, port={port}")
                return None
            
            # Use a list of arguments to prevent command injection
            command = [
                'docker', 'run', '-d',
                '-p', f'{port}:{challenge.docker_port}',
                challenge.docker_image
            ]
            
            logger.info(f"Starting container: {' '.join(command)}")
            
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30,  # Add timeout to prevent hanging
                shell=False  # Explicitly disable shell to prevent injection
            )
            
            if process.returncode == 0:
                container_id = process.stdout.strip()
                logger.info(f"Container started successfully: {container_id}")
                return container_id
            else:
                logger.error(f"Docker command failed: {process.stderr}")
                return None
                
        except subprocess.TimeoutExpired:
            logger.error("Docker command timed out")
            return None
        except Exception as e:
            logger.error(f"Error starting container: {e}")
            return None
    
    def _stop_docker_container(self, container_id):
        """Safely stop a Docker container."""
        try:
            # Validate container ID to prevent injection
            if not self._validate_container_id(container_id):
                logger.error(f"Invalid container ID: {container_id}")
                return False
            
            # Use a list of arguments to prevent command injection
            command = ['docker', 'stop', container_id]
            
            logger.info(f"Stopping container: {container_id}")
            
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30,  # Add timeout to prevent hanging
                shell=False  # Explicitly disable shell to prevent injection
            )
            
            if process.returncode == 0:
                logger.info(f"Container stopped successfully: {container_id}")
                return True
            else:
                logger.error(f"Docker stop command failed: {process.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error("Docker stop command timed out")
            return False
        except Exception as e:
            logger.error(f"Error stopping container: {e}")
            return False
    
    def _validate_docker_inputs(self, docker_image, docker_port, port):
        """Validate Docker command inputs to prevent injection."""
        import re
        
        # Validate port numbers
        if not isinstance(port, int) or not (1 <= port <= 65535):
            return False
        if not isinstance(docker_port, int) or not (1 <= docker_port <= 65535):
            return False
        
        # Validate Docker image name (allow alphanumeric, hyphens, underscores, dots, colons, slashes)
        if not re.match(r'^[a-zA-Z0-9._/-]+(?::[a-zA-Z0-9._-]+)?$', docker_image):
            return False
        
        return True
    
    def _validate_container_id(self, container_id):
        """Validate Docker container ID to prevent injection."""
        import re
        
        # Docker container IDs are hexadecimal strings (12 or 64 characters)
        if not re.match(r'^[a-f0-9]{12,64}$', container_id):
            return False
        
        return True
    