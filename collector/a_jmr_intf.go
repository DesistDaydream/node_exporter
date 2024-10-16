package collector

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/node_exporter/pkg/models"
)

type JMRIntfCollector struct {
	okFileUpdateTime        *prometheus.Desc
	okFileContentUpdateTime *prometheus.Desc
	logger                  log.Logger
}

func init() {
	registerCollector("jmr_intf", defaultDisabled, NewJMRIntfCollector)
}

func NewJMRIntfCollector(logger log.Logger) (Collector, error) {
	return &JMRIntfCollector{
		okFileUpdateTime: prometheus.NewDesc(
			prometheus.BuildFQName("jmr_intf", "ok_file", "update_time"),
			"ok 文件所在目录下，最后创建的文件的时间",
			[]string{"env", "security_data_type", "security_data_code"}, nil,
		),
		okFileContentUpdateTime: prometheus.NewDesc(
			prometheus.BuildFQName("jmr_intf", "ok_file_content", "update_time"),
			"ok 文件所在目录下，最后创建的文件中第一条日志的更新时间",
			[]string{"env", "security_data_type", "security_data_code"}, nil,
		),
		logger: logger,
	}, nil
}

func (c *JMRIntfCollector) Update(ch chan<- prometheus.Metric) error {
	for code, dataType := range models.JMRSecurityDataTypeCode {
		// 如果 code 的前两个字符为 00
		if code[:2] == "00" {
			okFileUtime, logUpdateTime := c.sampleOfOkFileUpdateTime(code, dataType.LogTimeFieldNum)
			ch <- prometheus.MustNewConstMetric(
				c.okFileUpdateTime,
				prometheus.GaugeValue,
				okFileUtime,
				"jmr_intf",
				dataType.Name,
				code,
			)
			ch <- prometheus.MustNewConstMetric(
				c.okFileContentUpdateTime,
				prometheus.GaugeValue,
				logUpdateTime,
				"jmr_intf",
				dataType.Name,
				code,
			)
		}
	}

	return nil
}

// ok文件更新时间
// return: 1. 最后更新的 ok 文件的更新时间 2. ok 文件中第一行日志的更新时间
func (c *JMRIntfCollector) sampleOfOkFileUpdateTime(securityDateCode string, logTimeFieldNum int) (float64, float64) {
	okFileDirPath := "/home/haohan/network/group"
	basePath := filepath.Join(okFileDirPath, securityDateCode, fmt.Sprintf("%s-0000", time.Now().Format("20060102")))
	files, err := filepath.Glob(filepath.Join(basePath, "*.ok"))
	if err != nil {
		level.Error(c.logger).Log("msg", fmt.Sprintf("无法获取 %v 的 ok 文件所在目录的内容", securityDateCode), "err", err)
		return 0, 0
	}

	if len(files) == 0 {
		level.Warn(c.logger).Log("msg", fmt.Sprintf("%v 目录中找不到 .ok 文件", basePath))
		return 0, 0
	}

	var (
		latestTime    time.Time
		latestFile    string
		okFileMtime   float64
		logUpdateTime float64
	)

	for _, file := range files {
		fileInfo, err := os.Stat(file)
		if err != nil {
			level.Error(c.logger).Log("msg", fmt.Sprintf("获取 %v 文件状态异常: %v", file, err), "err", err)
			continue
		}

		if fileInfo.ModTime().After(latestTime) {
			latestFile = file
			latestTime = fileInfo.ModTime()
		}
	}

	okFileMtime = float64(latestTime.Unix())
	logUpdateTime = c.getUpdateTimeOfLogInOkFile(latestFile, logTimeFieldNum)

	return okFileMtime, logUpdateTime
}

// 解析 ok 文件内容并获取第一条日志的更新时间
func (c *JMRIntfCollector) getUpdateTimeOfLogInOkFile(okFile string, logTimeFieldNum int) float64 {
	file, err := os.Open(okFile)
	if err != nil {
		level.Error(c.logger).Log("msg", fmt.Sprintf("无法打开 %v 文件", okFile), "err", err)
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// 解析第一行日志数据
	if scanner.Scan() {
		firstLine := scanner.Text()
		timeStr := c.getField(firstLine, logTimeFieldNum-1)
		chainaTimezone, err := time.LoadLocation("Asia/Shanghai")
		if err != nil {
			level.Error(c.logger).Log("msg", "无法加载时区", "err", err)
			return 0
		}
		t, err := time.ParseInLocation("2006-01-02 15:04:05", timeStr, chainaTimezone)
		if err != nil {
			return 0
		}
		return float64(t.Unix())
	}
	if err := scanner.Err(); err != nil {
		level.Error(c.logger).Log("msg", fmt.Sprintf("读取 %v 文件异常", okFile), "err", err)
		return 0
	}

	return 0
}

// 处理日志文本中的 | 符号，获取指定字段的值
func (c *JMRIntfCollector) getField(data string, fieldIndex int) string {
	fields := strings.Split(data, "|")
	if fieldIndex >= 0 && fieldIndex < len(fields) {
		return fields[fieldIndex]
	}

	level.Error(c.logger).Log("msg", fmt.Sprintf("无法获取第 [%v] 字段的值", fieldIndex+1))
	return ""
}
