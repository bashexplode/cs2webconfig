# script by Jesse Nebling (@bashexplode)
# idea based off of cs2modrewrite by ThreatExpress (github.com/threatexpress/cs2modrewrite)

import argparse
import sys
import re
import os


class CS2WebConfigRewrite:
    def __init__(self, teamserver, redirector, profile):
        self.c2server = teamserver
        self.redirect = redirector
        self.c2profile = profile

        self.webconfig_template = '''
<configuration>
    <system.webServer>
        <rewrite>
            <rules>
                <rule name="redirect get requests URI1" stopProcessing="true">
                    <match url="^{uri1}(.*)" />
                    <conditions>
                        <add input="{{HTTP_USER_AGENT}}" pattern="^{ua}$" />
                    </conditions>
                    <action type="Rewrite" url="{redirect}/{{R:0}}" appendQueryString="true" logRewrittenUrl="false" />
                </rule>

                <rule name="redirect get requests URI2" stopProcessing="true">
                    <match url="^{uri2}(.*)" />
                    <conditions>
                        <add input="{{HTTP_USER_AGENT}}" pattern="^{ua}$" />
                    </conditions>
                    <action type="Rewrite" url="{redirect}/{{R:0}}" appendQueryString="true" logRewrittenUrl="false" />
                </rule>

                <rule name="redirect get requests URI3" stopProcessing="true">
                    <match url="^{uri3}(.*)" />   
                    <conditions>
                        <add input="{{HTTP_USER_AGENT}}" pattern="^{ua}$" />
                    </conditions>
                    <action type="Rewrite" url="{redirect}/{uri3}" appendQueryString="true" logRewrittenUrl="false" />
                </rule>

                <rule name="redirect get requests URI4" stopProcessing="true">
                    <match url="^{uri4}(.*)" />
                    <conditions>
                        <add input="{{HTTP_USER_AGENT}}" pattern="^{ua}$" />
                    </conditions>
                    <action type="Rewrite" url="{redirect}/{uri4}" appendQueryString="true" logRewrittenUrl="false" />
                </rule>

                <rule name="redirect all other requests to index.html but allow images and css to be loaded" stopProcessing="true">
                    <match negate="true" url="^(index.html|(.*jpg)|(.*svg)|(.*gif)|(.*css)|(.*js)|(.*png)|(.*woff)|(.*ttf))$" /> 
                    <action type="Rewrite" url="/index.html" appendQueryString="true" /> 
                </rule>
            </rules>
        </rewrite>
    </system.webServer>
</configuration>
'''

    def webconfigparse(self):
        regex = re.compile(
            r'^(?:http|ftp)s?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)

        if re.match(regex, self.c2server) is None:
            print("[!] c2server is malformed. Are you sure {} is a valid URL?".format(self.c2server))
            sys.exit(1)

        profile = open(self.c2profile, "r")
        contents = profile.read()

        # Strip all single line comments (#COMMENT\n) from profile before searching so it doens't break our crappy parsing
        contents = re.sub(re.compile("#.*?\n"), "", contents)

        # Search Strings
        ua_string = "set useragent"
        http_get = "http-get"
        http_post = "http-post"
        set_uri = "set uri "

        http_stager = "http-stager"
        set_uri_86 = "set uri_x86"
        set_uri_64 = "set uri_x64"

        # Errors
        errorfound = False
        errors = "\n##########\n[!] ERRORS\n"

        # Get UserAgent
        if contents.find(ua_string) == -1:
            ua = ""
            errors += "[!] User-Agent Not Found\n"
            errorfound = True
        else:
            ua_start = contents.find(ua_string) + len(ua_string)
            ua_end = contents.find("\n", ua_start)
            ua = contents[ua_start:ua_end].strip()[1:-2]

        # Get HTTP GET URIs
        http_get_start = contents.find(http_get)
        if contents.find(set_uri) == -1:
            get_uri = ""
            errors += "[!] GET URIs Not Found\n"
            errorfound = True
        else:
            get_uri_start = contents.find(set_uri, http_get_start) + len(set_uri)
            get_uri_end = contents.find("\n", get_uri_start)
            get_uri = contents[get_uri_start:get_uri_end].strip()[1:-2]

        # Get HTTP POST URIs
        http_post_start = contents.find(http_post)
        if contents.find(set_uri) == -1:
            post_uri = ""
            errors += "[!] POST URIs Not Found\n"
            errorfound = True
        else:
            post_uri_start = contents.find(set_uri, http_post_start) + len(set_uri)
            post_uri_end = contents.find("\n", post_uri_start)
            post_uri = contents[post_uri_start:post_uri_end].strip()[1:-2]

        # Get HTTP Stager URIs x86
        http_stager_start = contents.find(http_stager)
        if contents.find(set_uri_86) == -1:
            stager_uri_86 = ""
            errors += "[!] x86 Stager URIs Not Found\n"
            errorfound = True
        else:
            stager_uri_start = contents.find(set_uri_86, http_stager_start) + len(set_uri_86)
            stager_uri_end = contents.find("\n", stager_uri_start)
            stager_uri_86 = contents[stager_uri_start:stager_uri_end].strip()[1:-2]

        # Get HTTP Stager URIs x64
        http_stager_start = contents.find(http_stager)
        if contents.find(set_uri_64) == -1:
            stager_uri_64 = ""
            errors += "[!] x64 Stager URIs Not Found\n"
            errorfound = True
        else:
            stager_uri_start = contents.find(set_uri_64, http_stager_start) + len(set_uri_64)
            stager_uri_end = contents.find("\n", stager_uri_start)
            stager_uri_64 = contents[stager_uri_start:stager_uri_end].strip()[1:-2]

        # Create URIs list - workaround only accepts 1 uri right now
        get_uris = get_uri.split()[0]
        post_uris = post_uri.split()[0]
        stager86_uris = stager_uri_86.split()[0]
        stager64_uris = stager_uri_64.split()[0]

        # Create UA in web.config rewrite syntax. No regex needed in UA string matching, but (). characters must be escaped
        ua_string = ua.replace('(', '\(').replace(')', '\)').replace('.', '\.')

        print("#### Save the following as web.config in the root web directory")
        print(self.webconfig_template.format(uri1=get_uris[1:], uri2=post_uris[1:], uri3=stager86_uris[1:], uri4=stager64_uris[1:], ua=ua_string, redirect=self.c2server))
        return self.webconfig_template.format(uri1=get_uris[1:], uri2=post_uris[1:], uri3=stager86_uris[1:], uri4=stager64_uris[1:], ua=ua_string, redirect=self.c2server)


class webconfigWriter():
    def __init__(self, outputfile):
        if outputfile:
            self.outputfile = outputfile
        else:
            self.outputfile = "web.config"

    def writefile(self, redirector, webconf):
        if not self.outputfile:
            ofile = redirector + ".web.config"
        else:
            ofile = self.outputfile
        firstline = open(ofile, 'w')
        firstline.close()
        with open(ofile, 'w') as f:
            f.write(webconf)
            print("[+] %s written to current directory" % ofile)


class Main:
    def __init__(self):
        parser = argparse.ArgumentParser(
            description='Uses the inventory.yaml file and C2 profile to generate web.config files per C2 grouping')
        parser.add_argument('-t', '--teamserver', default=False,
                            help='Cobalt Strike team server IP address or domain name')
        parser.add_argument('-r', '--redirector', default=False, help='Redirector IP address or domain name')
        parser.add_argument('-p', '--profile', default=False, help='C2 malleable profile (i.e. sick.profile)')
        parser.add_argument('-o', '--outputfile', default=False,
                            help='Output file name (i.e. web.config) - omitting will only output to standard out')

        args = parser.parse_args()

        self.teamserver = args.teamserver
        self.redirector = args.redirector
        self.profile = args.profile
        if args.outputfile:
            self.outputfile = args.outputfile
        else:
            self.outputfile = None

        self.go()

    def go(self):
        if os.path.isfile(self.profile):
            if os.stat(self.profile).st_size != 0:
                teamserver = self.teamserver
                redirector = self.redirector

                webconfparser = CS2WebConfigRewrite("https://" + teamserver, "https://" + redirector, self.profile)
                webconf = webconfparser.webconfigparse()

                if self.outputfile:
                    writer = webconfigWriter(self.outputfile)
                    writer.writefile(redirector, webconf)
            else:
                print("[!] %s is empty!" % self.profile)
        else:
            print("[!] %s does not exist!" % self.profile)


if __name__ == "__main__":
    try:
        Main()
    except KeyboardInterrupt:
        print("You killed it.")
        sys.exit()
