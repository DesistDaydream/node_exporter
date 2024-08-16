package models

// JRM 上报数据类型代码表
type JMRTypeData struct {
	Name string
}

var (
	JMRSecurityDataTypeCode map[string]JMRTypeData = map[string]JMRTypeData{
		"0001": {"主机受控事件"},
		"0002": {"网络攻击事件"},
		"0003": {"有害程序传播事件"},
		"0004": {"专题任务事件"},
		"0101": {"恶意资源监测记录"},
		"0102": {"恶意报文监测记录"},
		"0103": {"恶意样本监测记录"},
		"0201": {"处置结果记录"},
		"3002": {"心跳数据"},
	}
)
