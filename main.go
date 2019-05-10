package fps60

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
    "path"

	"github.com/WICG/webpackage/go/signedexchange"
	"github.com/julienschmidt/httprouter"
	"github.com/pkg/errors"

	"github.com/ampproject/amppackager/packager/certcache"
	"github.com/ampproject/amppackager/packager/signer"
	"github.com/ampproject/amppackager/packager/util"
	"github.com/ampproject/amppackager/packager/rtv"
)

var flagConfig = flag.String("config", "amppkg.toml", "Path to the config toml file.")
var flagDevelopment = flag.Bool("development", false, "True if this is a development server.")

// Prints errors returned by pkg/errors with stack traces.
func die(err interface{}) { log.Fatalf("%+v", err) }

// needed for local
//func main() {
//    Fps60()
//}

func Handle(w http.ResponseWriter, r *http.Request) {

	flag.Parse()
	if *flagConfig == "" {
		die("must specify --config")
	}
	configBytes, err := ioutil.ReadFile(*flagConfig)
	if err != nil {
		die(errors.Wrapf(err, "reading config at %s", *flagConfig))
	}
	config, err := util.ReadConfig(configBytes)
	if err != nil {
		die(errors.Wrapf(err, "parsing config at %s", *flagConfig))
	}

	// TODO(twifkak): Document what cert/key storage formats this accepts.
	certPem, err := ioutil.ReadFile(config.CertFile)
	if err != nil {
		die(errors.Wrapf(err, "reading %s", config.CertFile))
	}
	keyPem, err := ioutil.ReadFile(config.KeyFile)
	if err != nil {
		die(errors.Wrapf(err, "reading %s", config.KeyFile))
	}

	certs, err := signedexchange.ParseCertificates(certPem)
	if err != nil {
		die(errors.Wrapf(err, "parsing %s", config.CertFile))
	}
	if certs == nil || len(certs) == 0 {
		die(fmt.Sprintf("no cert found in %s", config.CertFile))
	}
	if !*flagDevelopment && !util.CanSignHttpExchanges(certs[0]) {
		die("cert is missing CanSignHttpExchanges extension")
	}
	// TODO(twifkak): Verify that certs[0] covers all the signing domains in the config.

	key, err := signedexchange.ParsePrivateKey(keyPem)
	if err != nil {
		die(errors.Wrapf(err, "parsing %s", config.KeyFile))
	}

	certCache := certcache.New(certs, config.OCSPCache)
	if err = certCache.Init(nil); err != nil {
		die(errors.Wrap(err, "building cert cache"))
	}
	rtvCache, err := rtv.New()
	if err != nil {
		die(errors.Wrap(err, "initializing rtv cache"))
	}

	rtvCache.StartCron()
	defer rtvCache.StopCron()

	var overrideBaseURL *url.URL
	if *flagDevelopment {
		overrideBaseURL, err = url.Parse(fmt.Sprintf("https://localhost:%d/", config.Port))
		if err != nil {
			die(errors.Wrap(err, "parsing development base URL"))
		}
	}

	packager, err := signer.New(certs[0], key, config.URLSet, rtvCache, certCache.IsHealthy,
		overrideBaseURL, /*requireHeaders=*/!*flagDevelopment)
	if err != nil {
		die(errors.Wrap(err, "building packager"))
	}

    log.Println("Cert available:", path.Join("/amppkg/cert", util.CertName(certs[0])))

    router := httprouter.New()
    router.GET("/priv/doc/*signURL", packager.ServeHTTP)
    router.GET(path.Join("/amppkg/cert", util.CertName(certs[0])), certCache.ServeHTTP)

    log.Fatal(http.ListenAndServe(":8080", router))
	log.Println("Serving on port", config.Port)


}
