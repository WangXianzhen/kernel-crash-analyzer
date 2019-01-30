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
#  [ ] Add debug for incorrect kernel version numbers passed in
#  [ ] Detect host environment, use dpkg vs. ar where necessary
#  [ ] Add optional '-d' arg to specify an output directory, else pwd
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
def download_kernel(app, kernel, headers):

    kernel_size = int(headers['Content-Length'])

    do_download = False
    if os.path.exists(kernel):
        if len(open(kernel, 'rb').read()) != kernel_size:
            do_download = True
            output_file = open(kernel, "ab")
            headers.update({'Range': 'bytes=%s-%s'
                           % (os.path.getsize(kernel), kernel_size)})

    else:
        do_download = True
        output_file = open(kernel, "wb")

    if do_download:
        print('Downloading...: {}{}'.format(app.k_url, kernel))

        kernel_ddeb = requests.get('{}/{}'.format(app.k_url, kernel),
                                   headers=app.headers, stream=True)

        bar_width = 20
        progress = '#' * int(os.path.getsize(kernel) /
                             (kernel_size / bar_width))
        bar_template = "%(label)s [{}%(bar)s] %(info)s".format(progress)

        progress_width = bar_width - int(os.path.getsize(kernel) /
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
def unpack_debug_kernel(app, kver, kernel):

    print("Unpacking....: {}".format(kernel))
    subprocess.run(['ar', 'x', kernel], check=True)

    if not os.path.exists('{}_debug'.format(kver)):
        os.makedirs('{}_debug'.format(kver))

    # print("Extracting...: kernel 'boot/vmlinux-{}'...".format(kver))
    # subprocess.run(['tar', 'xvf', 'data.tar.xz', '-C',
    #                '{}_debug'.format(kver), kernel_path], check=True)

    print("Removing.....: control.tar.gz, data.tar.gz")
    os.unlink('data.tar.xz')


###############################################################
def dump_symbols(app, kver):

    with open("debug.S", "wb", 0) as out:
        subprocess.run(['objdump', '-l', '-D',
                        '{}_debug/usr/lib/debug/boot/vmlinux-{}'.format(kver, kver)],
                       stdout=out, check=True)


@click.command()
@click.option('-a', '--arch', 'arch',
              type=click.Choice(['amd64',
                                 'i386',
                                 'armhf',
                                 'arm64',
                                 's390x',
                                 'ppc64']),
              required=True,
              help='Architecture to filter on')
@click.option('-k', '--kernel-version', 'kver',
              required=True,
              help='Kernel version to filter on')
###############################################################
def main(arch, kver):

    app = Kca()

    r = app.session.get(
        app.k_url).text.encode('ascii', 'ignore').decode('utf-8')

    kernels = html.fromstring(r)
    links = kernels.xpath('//a/@href')

    for kernel in links:
        if arch in kernel and kver in kernel:
            r = app.session.head('{}/{}'.format(app.k_url, kernel))
            download_kernel(app, kernel, r.headers)
            unpack_debug_kernel(app, kver, kernel)
            dump_symbols(app, kver)


if __name__ == "__main__":
    main()
