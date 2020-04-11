#-------------------------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See https://go.microsoft.com/fwlink/?linkid=2090316 for license information.
#-------------------------------------------------------------------------------------------------------------

FROM python:3.6

# Avoid warnings by switching to noninteractive
ENV DEBIAN_FRONTEND=noninteractive

# This Dockerfile adds a non-root user with sudo access. Use the "remoteUser"
# property in devcontainer.json to use it. On Linux, the container user's GID/UIDs
# will be updated to match your local UID/GID (when using the dockerFile property).
# See https://aka.ms/vscode-remote/containers/non-root-user for details.
ARG USERNAME=cc451
ARG USER_UID=1000
ARG USER_GID=$USER_UID
ARG WORKSPACE_ROOT=/workspaces/2020-lab1
# Uncomment the following COPY line and the corresponding lines in the `RUN` command if you wish to
# include your requirements in the image itself. It is suggested that you only do this if your
# requirements rarely (if ever) change.
# COPY requirements.txt /tmp/pip-tmp/

# Configure apt and install packages
RUN apt-get update \
    && apt-get -y install --no-install-recommends apt-utils dialog 2>&1 \
    #
    # Verify git, process tools, lsb-release (common in install instructions for CLIs) installed
    # Install wget, zsh, tftp server
    && apt-get -y install git openssh-client less iproute2 procps lsb-release vim wget zsh tftp tftpd-hpa\
    #
    # Set zsh as default shell
    && chsh -s $(which zsh) \
    #
    #
    # Install pylint
    && pip --disable-pip-version-check --no-cache-dir install pylint autopep8 'pytest==5.4.1' \
    #
    # Update Python environment based on requirements.txt
    # && pip --disable-pip-version-check --no-cache-dir install -r /tmp/pip-tmp/requirements.txt \
    # && rm -rf /tmp/pip-tmp \
    #
    # Create a non-root user to use if preferred - see https://aka.ms/vscode-remote/containers/non-root-user.
    && groupadd --gid $USER_GID $USERNAME \
    && useradd -s /bin/zsh --uid $USER_UID --gid $USER_GID -m $USERNAME \
    # [Optional] Add sudo support for the non-root user
    && apt-get install -y sudo \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME\
    && chmod 0440 /etc/sudoers.d/$USERNAME \
    #
    # Clean up
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

#TODO change the server.config to be embedded in the Dockerfile 
COPY app/lab1/configs/server.config /etc/default/tftpd-hpa

RUN chown -R tftp /srv/tftp
RUN chown $USERNAME /srv/tftp

WORKDIR ${WORKSPACE_ROOT}
ADD app/scripts app/scripts
ADD app/requirements.txt app/requirements.txt

RUN chown -R $USERNAME ${WORKSPACE_ROOT}

RUN su - $USERNAME -c "zsh ${WORKSPACE_ROOT}/app/scripts/setup_environment.sh"
RUN su - $USERNAME -c "pip install -r ${WORKSPACE_ROOT}/app/requirements.txt"

USER $USERNAME
# Switch back to dialog for any ad-hoc use of apt-get
ENV DEBIAN_FRONTEND=dialog

