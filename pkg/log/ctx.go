package log

import "github.com/sirupsen/logrus"

type Entry = logrus.Entry

// Fields type to pass to "WithFields".
type Fields = map[string]any

// L is an alias for the standard logger.
var L = &Entry{
	Logger: logrus.StandardLogger(),
	// Default is three fields plus a little extra room.
	Data: make(Fields, 6),
}

func init() {
	//L.Logger.SetReportCaller(true)
}
