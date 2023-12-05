package elasticsearch

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/cprobe/cprobe/lib/logger"
	"github.com/cprobe/cprobe/plugins"
	"github.com/cprobe/cprobe/plugins/elasticsearch/collector"
	"github.com/cprobe/cprobe/plugins/elasticsearch/pkg/clusterinfo"
	"github.com/cprobe/cprobe/types"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/version"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"
)

type Global struct {
	Username string `toml:"username"`
	Password string `toml:"password"`
}

type Config struct {
	BaseDir string  `toml:"-"`
	Global  *Global `toml:"global"`

	EsTimeout               time.Duration `toml:"es_timeout"`
	EsAllNodes              *bool         `toml:"es_all_nodes"`
	EsNode                  string        `toml:"es_node"`
	EsExportIndices         *bool         `toml:"es_export_indices"`
	EsExportIndicesSettings *bool         `toml:"es_export_indices_settings"`
	EsExportIndicesMappings *bool         `toml:"es_export_indices_mappings"`
	EsExportIndexAliases    *bool         `toml:"es_export_index_aliases"`
	EsExportILM             *bool         `toml:"es_export_ilm"`
	EsExportShards          *bool         `toml:"es_export_shards"`
	EsExportSLM             *bool         `toml:"es_export_slm"`
	EsExportDataStream      *bool         `toml:"es_export_data_stream"`
	EsClusterInfoInterval   time.Duration `toml:"es_cluster_info_interval"`
	EsCA                    string        `toml:"es_ca"`
	EsClientPrivateKey      string        `toml:"es_client_private_key"`
	EsClientCert            string        `toml:"es_client_cert"`
	EsInsecureSkipVerify    *bool         `toml:"es_insecure_skip_verify"`
}

type ElasticSearch struct {
	// 这个数据结构中未来如果有变量，千万要小心并发使用变量的问题
}

func init() {
	plugins.RegisterPlugin(types.PluginElasticSearch, &ElasticSearch{})
}

const name = "elasticsearch_exporter"

type transportWithAPIKey struct {
	underlyingTransport http.RoundTripper
	apiKey              string
}

func (t *transportWithAPIKey) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("Authorization", fmt.Sprintf("ApiKey %s", t.apiKey))
	return t.underlyingTransport.RoundTrip(req)
}

func createTLSConfig(pemFile, pemCertFile, pemPrivateKeyFile string, insecureSkipVerify bool) *tls.Config {
	tlsConfig := tls.Config{}
	if insecureSkipVerify {
		// pem settings are irrelevant if we're skipping verification anyway
		tlsConfig.InsecureSkipVerify = true
	}
	if len(pemFile) > 0 {
		rootCerts, err := loadCertificatesFrom(pemFile)
		if err != nil {
			log.Fatalf("Couldn't load root certificate from %s. Got %s.", pemFile, err)
			return nil
		}
		tlsConfig.RootCAs = rootCerts
	}
	if len(pemCertFile) > 0 && len(pemPrivateKeyFile) > 0 {
		// Load files once to catch configuration error early.
		_, err := loadPrivateKeyFrom(pemCertFile, pemPrivateKeyFile)
		if err != nil {
			log.Fatalf("Couldn't setup client authentication. Got %s.", err)
			return nil
		}
		// Define a function to load certificate and key lazily at TLS handshake to
		// ensure that the latest files are used in case they have been rotated.
		tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return loadPrivateKeyFrom(pemCertFile, pemPrivateKeyFile)
		}
	}
	return &tlsConfig
}

func loadCertificatesFrom(pemFile string) (*x509.CertPool, error) {
	caCert, err := os.ReadFile(pemFile)
	if err != nil {
		return nil, err
	}
	certificates := x509.NewCertPool()
	certificates.AppendCertsFromPEM(caCert)
	return certificates, nil
}

func loadPrivateKeyFrom(pemCertFile, pemPrivateKeyFile string) (*tls.Certificate, error) {
	privateKey, err := tls.LoadX509KeyPair(pemCertFile, pemPrivateKeyFile)
	if err != nil {
		return nil, err
	}
	return &privateKey, nil
}

func (*ElasticSearch) ParseConfig(baseDir string, bs []byte) (any, error) {
	var c Config
	err := toml.Unmarshal(bs, &c)
	if err != nil {
		return nil, err
	}

	c.BaseDir = baseDir

	return &c, nil
}

// Scrape elasticsearch_exporter 原来的很多参数都是通过命令行传的，在 cprobe 的场景下，需要改造
// cprobe 是并发抓取很多个数据库实例的监控数据，不同的数据库实例其抓取参数可能不同
// 如果直接修改 collector pkg 下面的变量，就会有并发使用变量的问题
// 把这些自定义参数封装到一个一个的 collector.Scraper 对象中，每个 target 抓取时实例化这些 collector.Scraper 对象
func (*ElasticSearch) Scrape(ctx context.Context, address string, c any, ss *types.Samples) error {
	// 这个方法中如果要对配置 c 变量做修改，一定要 clone 一份之后再修改，因为并发的多个 target 共享了一个 c 变量
	cfg := c.(*Config)
	if !strings.Contains(address, "://") {
		address = "http://" + address
	}

	esURL, err := url.Parse(address)
	if err != nil {
		return fmt.Errorf("failed to parse es_url")
	}

	esUsername := cfg.Global.Username
	esPassword := cfg.Global.Password

	if esUsername != "" && esPassword != "" {
		esURL.User = url.UserPassword(esUsername, esPassword)
	}

	// returns nil if not provided and falls back to simple TCP.
	tlsConfig := createTLSConfig(cfg.EsCA, cfg.EsClientCert, cfg.EsClientPrivateKey, *cfg.EsInsecureSkipVerify)

	var httpTransport http.RoundTripper

	httpTransport = &http.Transport{
		TLSClientConfig: tlsConfig,
		Proxy:           http.ProxyFromEnvironment,
	}

	esAPIKey := os.Getenv("ES_API_KEY")

	if esAPIKey != "" {
		httpTransport = &transportWithAPIKey{
			underlyingTransport: httpTransport,
			apiKey:              esAPIKey,
		}
	}

	httpClient := &http.Client{
		Timeout:   cfg.EsTimeout,
		Transport: httpTransport,
	}

	// version metric
	prometheus.MustRegister(version.NewCollector(name))

	// create the exporter
	exporter, err := collector.NewElasticsearchCollector(
		[]string{},
		collector.WithElasticsearchURL(esURL),
		collector.WithHTTPClient(httpClient),
	)
	if err != nil {
		return errors.Wrap(err, "failed to create Elasticsearch collector")
	}
	prometheus.MustRegister(exporter)

	// TODO(@sysadmind): Remove this when we have a better way to get the cluster name to down stream collectors.
	// cluster info retriever
	clusterInfoRetriever := clusterinfo.New(httpClient, esURL, cfg.EsClusterInfoInterval)

	prometheus.MustRegister(collector.NewClusterHealth(httpClient, esURL))
	prometheus.MustRegister(collector.NewNodes(httpClient, esURL, *cfg.EsAllNodes, cfg.EsNode))

	if *cfg.EsExportIndices || *cfg.EsExportShards {
		prometheus.MustRegister(collector.NewShards(httpClient, esURL))
		iC := collector.NewIndices(httpClient, esURL, *cfg.EsExportShards, *cfg.EsExportIndexAliases)
		prometheus.MustRegister(iC)
		if registerErr := clusterInfoRetriever.RegisterConsumer(iC); registerErr != nil {
			logger.Errorf("msg", "failed to register indices collector in cluster info")
			return registerErr
		}
	}

	if *cfg.EsExportSLM {
		prometheus.MustRegister(collector.NewSLM(httpClient, esURL))
	}

	if *cfg.EsExportDataStream {
		prometheus.MustRegister(collector.NewDataStream(httpClient, esURL))
	}

	if *cfg.EsExportIndicesSettings {
		prometheus.MustRegister(collector.NewIndicesSettings(httpClient, esURL))
	}

	if *cfg.EsExportIndicesMappings {
		prometheus.MustRegister(collector.NewIndicesMappings(httpClient, esURL))
	}

	if *cfg.EsExportILM {
		prometheus.MustRegister(collector.NewIlmStatus(httpClient, esURL))
		prometheus.MustRegister(collector.NewIlmIndicies(httpClient, esURL))
	}

	// Create a context that is cancelled on SIGKILL or SIGINT.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	// start the cluster info retriever
	switch runErr := clusterInfoRetriever.Run(ctx); runErr {
	case nil:
		logger.Infof(
			"msg", "started cluster info retriever",
			"interval", (cfg.EsClusterInfoInterval).String(),
		)
	case clusterinfo.ErrInitialCallTimeout:
		logger.Infof("msg", "initial cluster info call timed out")
	default:
		logger.Errorf("msg", "failed to run cluster info retriever", "err", err)
		return err
	}

	// register cluster info retriever as prometheus collector
	prometheus.MustRegister(clusterInfoRetriever)

	//ch := make(chan prometheus.Metric)
	//go func() {
	//	exporter.Collect(ch)
	//	close(ch)
	//}()
	//
	//for m := range ch {
	//	if err := ss.AddPromMetric(m); err != nil {
	//		logger.Warnf("failed to transform prometheus metric: %s", err)
	//	}
	//}

	return nil
}
