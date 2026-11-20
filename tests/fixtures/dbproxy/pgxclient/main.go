// Command pgxclient 用真实 Go 驱动（pgx/v5，扩展查询协议）验证 KeyKoi 数据库代理。
// 它走 Parse/Bind/Describe/Execute/Sync，覆盖 psql 简单查询协议之外的路径。
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
)

func main() {
	dsn := flag.String("dsn", "", "PostgreSQL connection string (through the proxy)")
	query := flag.String("query", "select $1::int + 1", "parameterized query to run")
	value := flag.Int("value", 41, "integer argument")
	flag.Parse()

	if *dsn == "" {
		fmt.Fprintln(os.Stderr, "pgxclient: --dsn is required")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, *dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgxclient: connect: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close(context.Background())

	var result int
	if err := conn.QueryRow(ctx, *query, *value).Scan(&result); err != nil {
		fmt.Fprintf(os.Stderr, "pgxclient: query: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(result)
}
