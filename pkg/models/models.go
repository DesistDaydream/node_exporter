// Package models ...
package models

// JMRTypeData JRM 上报数据类型代码表
type JMRTypeData struct {
	Name            string
	LogTimeFieldNum int // 日志条目更新时间所在字段的号
}

var (
	JMRSecurityDataTypeCode map[string]JMRTypeData = map[string]JMRTypeData{
		"0001": {"主机受控事件", 11},
		"0002": {"网络攻击事件", 12},
		"0003": {"有害程序传播事件", 16},
		"0004": {"专题任务事件", 18},
		"0005": {"样本文件", 11},
		"0007": {"工控设备数据", 19},
		"0101": {"恶意资源监测记录", 0},
		"0102": {"恶意报文监测记录", 0},
		"0103": {"恶意样本监测记录", 0},
		"0201": {"处置结果记录", 0},
		"3002": {"心跳数据", 0},
	}
)
