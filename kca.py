#!/usr/bin/env python
#####################################################################
#        _._
#       /_ _`.      (c) 2019, David A. Desrosiers
#       (.(.)|      setuid at gmail dot com
#       |\_/'|
#       )____`\     If you find this useful, please drop me
#      //_V _\ \    an email, or send me bug reports if you find
#     ((  |  `(_)   problems with it.
#    / \> '   / \
#    \  \.__./  /   Kernel Crash Analyzer v1.0
#     `-'    `-'
#
# TODO: # to be checked off when completed
#
#  [x] Add debug for incorrect kernel version numbers passed in
#  [ ] Detect host environment, use dpkg vs. ar where necessary
#  [x] Add optional '-d' arg to specify an output directory, else pwd
#  [ ] Support cleanly slicing Call Trace pragma from logs
#  [ ] Jinja2 support for output 'report' of final results
#
#####################################################################
from lxml import html
import click
import os
import requests
import subprocess


###############################################################
class Kca:

    def __init__(self):
        self.ua = 'Kernel Analysis Tool v1.0'
        self.headers = {
            'User-Agent': self.ua,
            'Accept-Encoding': 'gzip',
            'Connection': 'keep-alive',
        }

        self.proxies = {}
        self.k_url = 'http://ddebs.ubuntu.com/pool/main/l/linux/'

        self.session = requests.Session()


###############################################################
def download_kernel(app, dest_dir, kernel, kernel_size):

    kernel_path = '{}/{}'.format(dest_dir, kernel)

    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)

    do_download = False
    if os.path.exists(kernel_path):
        if len(open(kernel_path, 'rb').read()) != kernel_size:
            do_download = True
            output_file = open(kernel, "ab")
            app.headers.update({'Range': 'bytes=%s-%s'
                               % (os.path.getsize(kernel_path),
                                kernel_size)})

    else:
        do_download = True
        output_file = open(kernel_path, "wb")

    if do_download:
        print('Downloading...: {}{}'.format(app.k_url, kernel))

        kernel_ddeb = requests.get('{}/{}'.format(app.k_url, kernel),
                                   headers=app.headers, stream=True)

        bar_width = 20
        progress = '#' * int(os.path.getsize(kernel_path) /
                             (kernel_size / bar_width))
        bar_template = "%(label)s [{}%(bar)s] %(info)s".format(progress)

        progress_width = bar_width - int(os.path.getsize(kernel_path) /
                                         (kernel_size / bar_width))
        with click.progressbar(kernel_ddeb.iter_content(1024),
                               bar_template=bar_template,
                               info_sep='|',
                               label=click.style(kernel.rjust(35), fg='green'),
                               show_pos=False,
                               length=kernel_size,
                               show_eta=True,
                               show_percent=True,
                               width=(progress_width)) as bar:
            for chunk in bar:
                output_file.write(chunk)
                bar.update(1024)


###############################################################
def unpack_debug_kernel(app, dest_dir, kver, kernel):

    kernel_path = './usr/lib/debug/boot/vmlinux-{}'.format(kver)

    print("Unpacking....: {}".format(kernel))
    subprocess.run(['ar', 'x', '{}/{}'.format(dest_dir, kernel),
                    '{}/data.tar.xz'.format(dest_dir)], check=True)

    print("Extracting...: '{}'...".format(kernel_path))
    subprocess.run(['tar', 'xvf', 'data.tar.xz', '-C',
                   dest_dir, kernel_path],
                   check=True)

    print("Removing.....: data.tar.gz")
    os.unlink('data.tar.xz')


###############################################################
def dump_symbols(app, dest_dir, kver):

    with open("debug.S", "wb", 0) as out:
        subprocess.run(['objdump', '-l', '-d',
                        '{}/usr/lib/debug/boot/vmlinux-{}'
                        .format(dest_dir, kver)],
                       stdout=out, check=True)


@click.command()
@click.option('-a', '--arch', 'arch',
              type=click.Choice(['amd64', 'i386',
                                 'armhf', 'arm64',
                                 's390x', 'ppc64']),
              required=True,
              help='Architecture to filter on')
@click.option('-k', '--kernel-version', 'kver',
              required=True,
              help='Kernel version to filter on')
@click.option('-d', '--dest-dir', 'dest_dir',
              default=os.getcwd())
###############################################################
def main(arch, kver, dest_dir):

    app = Kca()

    r = app.session.get(
        app.k_url).text.encode('ascii', 'ignore').decode('utf-8')

    kernels = html.fromstring(r)
    links = kernels.xpath('//a/@href')

    for kernel in links:
        if arch in kernel and kver in kernel:
            r = app.session.head('{}/{}'.format(app.k_url, kernel))
            kernel_size = int(r.headers['Content-Length'])
            download_kernel(app, dest_dir, kernel, kernel_size)
            unpack_debug_kernel(app, dest_dir, kver, kernel)
            dump_symbols(app, dest_dir, kver)
        else:
            print("Kernel {} not found. Is this the version kernel?"
                  .format(kver))
            return


if __name__ == "__main__":
    main()
