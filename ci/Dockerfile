FROM ubuntu:wily
MAINTAINER Jim Kuhn <j.kuhn@computer.org>
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends git-core && apt-get clean
RUN /bin/echo -e '\
apt-get update && apt-get install -y --no-install-recommends sudo && sudo apt-get clean\n\
echo '"'"'root:docker'"'"'|chpasswd && useradd -ms /bin/bash user && echo '"'"'user:user'"'"'|chpasswd && echo '"'"'umask 000'"'"' >>/home/user/.profile\n\
[ -f /etc/sudoers ] && echo "user ALL=NOPASSWD: ALL" >>/etc/sudoers\n\
usermod -aG audio user\n\
'|/bin/bash -l
USER user
WORKDIR /home/user
RUN /bin/echo -e '\
sudo apt-get update\n\
sudo apt-get install -y --no-install-recommends build-essential g++ cmake\n\
sudo apt-get clean\n\
'|/bin/bash -l
RUN git clone --depth 1 git://github.com/JimKuhn/extempore
RUN mkdir extempore/cmake-build && cd extempore/cmake-build && cmake ..
RUN sudo apt-get install -y --no-install-recommends libasound2-dev libgl1-mesa-dev libsndfile1-dev libassimp3v5 libglfw3 libportmidi-dev && sudo apt-get clean
RUN sudo apt-get install -y --no-install-recommends python && sudo apt-get clean
# new glfw3 requirements
RUN sudo apt-get install -y libxrandr-dev libxinerama-dev libxcursor-dev
RUN cd extempore/cmake-build && make -j $(($(nproc) + 1)) && sudo make install
# RUN cd extempore/cmake-build && make aot
RUN /bin/echo -e '\
git clone --depth 1 git://github.com/extemporelang/kiss_fft\n\
cd kiss_fft && mkdir cmake-build && cd cmake-build && cmake ..\n\
make -j $(($(nproc) + 1)) && sudo make install\n\
'|/bin/bash -l
RUN /bin/echo -e '\
git clone --depth 1 git://github.com/extemporelang/stb\n\
cd stb && mkdir cmake-build && cd cmake-build && cmake ..\n\
make -j $(($(nproc) + 1)) && sudo make install\n\
'|/bin/bash -l
RUN /bin/echo -e '\
git clone --depth 1 git://github.com/extemporelang/nanovg\n\
cd nanovg && mkdir cmake-build && cd cmake-build && cmake ..\n\
make -j $(($(nproc) + 1)) && sudo make install\n\
'|/bin/bash -l
RUN cd extempore/cmake-build && make aot_extended
EXPOSE 7099
CMD ["extempore"]
