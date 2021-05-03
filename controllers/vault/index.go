package vault

import (
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/patrickmn/go-cache"
	keyhub "github.com/topicuskeyhub/go-keyhub"
	keyhubclient "github.com/topicuskeyhub/go-keyhub"
	"github.com/topicusonderwijs/keyhub-vault-operator/controllers/metrics"
)

type VaultRecordWithGroup struct {
	Group  keyhubclient.Group
	Record keyhubclient.VaultRecord
}

type VaultIndexCache interface {
	Get(client *keyhub.Client) (map[string]VaultRecordWithGroup, error)
	Flush()
}

type vaultIndexCache struct {
	log   logr.Logger
	cache *cache.Cache
	mutex *sync.Mutex
}

func NewVaultIndexCache(log logr.Logger) VaultIndexCache {
	return &vaultIndexCache{
		log:   log,
		cache: cache.New(10*time.Minute, 15*time.Minute),
		mutex: &sync.Mutex{},
	}
}

func (c *vaultIndexCache) Get(client *keyhub.Client) (map[string]VaultRecordWithGroup, error) {
	if records, found := c.cache.Get(client.ID); found {
		return records.(map[string]VaultRecordWithGroup), nil
	}

	metrics.KeyHubApiRequests.WithLabelValues("group", "list").Inc()
	groups, err := client.Groups.List()
	if err != nil {
		return nil, err
	}

	result := make(map[string]VaultRecordWithGroup)
	for _, group := range groups {
		// log.Info("Found KeyHub group", "uuid", group.UUID, "name", group.Name)
		metrics.KeyHubApiRequests.WithLabelValues("vault", "list").Inc()
		records, err := client.Vaults.GetRecords(&group)
		if err != nil {
			return nil, err
		}
		for _, record := range records {
			c.log.Info("Found Keyhub vault record", "group", group.UUID, "uuid", record.UUID, "name", record.Name)
			// records = append(records, VaultRecordWithGroup{group: group, record: record})

			result[record.UUID] = VaultRecordWithGroup{Group: group, Record: record}
		}
	}

	c.cache.SetDefault(client.ID, result)

	return result, nil
}

func (c *vaultIndexCache) Flush() {
	c.cache.Flush()
}
