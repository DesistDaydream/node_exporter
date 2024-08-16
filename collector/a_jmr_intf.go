package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/node_exporter/pkg/models"
)

type JMRIntfCollector struct {
	okFileUpdateTime *prometheus.Desc
	logger           log.Logger
}

func init() {
	registerCollector("mycollector", defaultEnabled, NewMyCollector)
}

func NewMyCollector(logger log.Logger) (Collector, error) {
	return &JMRIntfCollector{
		okFileUpdateTime: prometheus.NewDesc(
			prometheus.BuildFQName("jmr_intf", "ok_file", "update_time"),
			"ok 文件所在目录下，最后创建的文件的时间",
			[]string{"env", "security_data_type", "security_data_code"}, nil,
		),
		logger: logger,
	}, nil
}

func (c *JMRIntfCollector) Update(ch chan<- prometheus.Metric) error {
	for code, dataType := range models.JMRSecurityDataTypeCode {
		// 如果 code 的前两个字符为 00
		if code[:2] == "00" {
			ch <- prometheus.MustNewConstMetric(
				c.okFileUpdateTime,
				prometheus.GaugeValue,
				c.sampleOfOkFileUpdateTime(code),
				"jmr_intf",
				dataType.Name,
				code,
			)
		}

	}

	return nil
}

// ok文件更新时间
func (c *JMRIntfCollector) sampleOfOkFileUpdateTime(secruityDateCode string) float64 {
	okFileDirPath := "/home/haohan/network/group"
	basePath := filepath.Join(okFileDirPath, secruityDateCode, fmt.Sprintf("%s-0000", time.Now().Format("20060102")))
	files, err := filepath.Glob(filepath.Join(basePath, "*.ok"))
	if err != nil {
		level.Error(c.logger).Log("msg", fmt.Sprintf("无法获取 %v 的 ok 文件所在目录的内容", secruityDateCode), "err", err)
		return 0
	}

	var latestTime time.Time

	for _, file := range files {
		fileInfo, err := os.Stat(file)
		if err != nil {
			level.Error(c.logger).Log("msg", fmt.Sprintf("获取 %v 文件状态异常: %v", file, err), "err", err)
			continue
		}

		if fileInfo.ModTime().After(latestTime) {
			latestTime = fileInfo.ModTime()
		}
	}

	return float64(latestTime.Unix())
}
