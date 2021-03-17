/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.knox.gateway.services.token.impl;

import java.sql.SQLException;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.knox.gateway.config.GatewayConfig;
import org.apache.knox.gateway.services.ServiceLifecycleException;
import org.apache.knox.gateway.services.security.token.UnknownTokenException;

public class JDBCTokenStateService extends DefaultTokenStateService {
  private TokenStateDatabase tokenDatabase;

  @Override
  public void init(GatewayConfig config, Map<String, String> options) throws ServiceLifecycleException {
    super.init(config, options);
    try {
      this.tokenDatabase = new TokenStateDatabase(config.getGatewaySecurityDir() + "/tokenDb");
    } catch (Exception e) {
      throw new ServiceLifecycleException("Error while initiating JDBCTokenStateService: " + e, e);
    }
  }

  @Override
  public void start() throws ServiceLifecycleException {
    super.start();
    try {
      this.tokenDatabase.start();
    } catch (Exception e) {
      throw new ServiceLifecycleException("Error while starting JDBCTokenStateService: " + e.getMessage(), e);
    }
  }

  @Override
  public void stop() throws ServiceLifecycleException {
    super.stop();
    try {
      this.tokenDatabase.stop();
    } catch (SQLException e) {
      throw new ServiceLifecycleException("Error while stopping JDBCTokenStateService: " + e.getMessage(), e);
    }
  }

  @Override
  public void addToken(String tokenId, long issueTime, long expiration, long maxLifetimeDuration) {
    super.addToken(tokenId, issueTime, expiration, maxLifetimeDuration);
    try {
      final boolean added = tokenDatabase.addToken(tokenId, issueTime, expiration, maxLifetimeDuration);
      if (added) {
        log.savedTokenInDatabase(tokenId);
      } else {
        log.failedToSaveTokenInDatabase(tokenId);
      }
    } catch (SQLException e) {
      log.errorSavingTokenInDatabase(tokenId, e.getMessage(), e);
    }
  }

  @Override
  protected void removeTokens(Set<String> tokenIds) {
    try {
      boolean removed = tokenDatabase.removeTokens(tokenIds);
      if (removed) {
        log.removedTokensFromDatabase(tokenIds.size());
      } else {
        log.failedToRemoveTokensFromDatabase(tokenIds.size());
      }
    } catch (SQLException e) {
      log.errorRemovingTokensFromDatabase(tokenIds.size(), e.getMessage(), e);
    }
    super.removeTokens(tokenIds);
  }

  @Override
  public long getTokenExpiration(String tokenId, boolean validate) throws UnknownTokenException {
    try {
      // check the in-memory cache, then
      return super.getTokenExpiration(tokenId, validate);
    } catch (UnknownTokenException e) {
      // It's not in memory
    }

    long expiration = 0;
    try {
      expiration = tokenDatabase.getTokenExpiration(tokenId);
      log.fetchedExpirationFromDatabase(tokenId, expiration);
    } catch (SQLException e) {
      log.errorFetchingExpirationFromDatabase(tokenId, e.getMessage(), e);
    }
    return expiration;
  }

  @Override
  protected void updateExpiration(String tokenId, long expiration) {
    // Update in-memory
    super.updateExpiration(tokenId, expiration);

    try {
      final boolean updated = tokenDatabase.updateExpiration(tokenId, expiration);
      if (updated) {
        log.updatedExpirationInDatabase(tokenId, expiration);
      } else {
        log.failedToUpdateExpirationInDatabase(tokenId, expiration);
      }
    } catch (SQLException e) {
      log.errorUpdatingExpirationInDatabase(tokenId, e.getMessage(), e);
    }
  }

  @Override
  protected long getMaxLifetime(String tokenId) {
    long maxLifetime = super.getMaxLifetime(tokenId);

    // If there is no result from the in-memory collection, proceed to check the Database
    if (maxLifetime < 1L) {
      try {
        maxLifetime = tokenDatabase.getMaxLifetime(tokenId);
        log.fetchedMaxLifetimeFromDatabase(tokenId, maxLifetime);
      } catch (SQLException e) {
        log.errorFetchingMaxLifetimeFromDatabase(tokenId, e.getMessage(), e);
      }
    }
    return maxLifetime;
  }

  @Override
  protected boolean isUnknown(String tokenId) {
    boolean isUnknown = super.isUnknown(tokenId);

    // If it's not in the cache, then check in the Database
    if (isUnknown) {
      try {
        isUnknown = tokenDatabase.getMaxLifetime(tokenId) < 0;
      } catch (SQLException e) {
        log.errorFetchingMaxLifetimeFromDatabase(tokenId, e.getMessage(), e);
      }
    }
    return isUnknown;
  }

  @Override
  protected List<String> getTokenIds() {
    List<String> tokenIds = new LinkedList<String>();
    try {
      tokenIds = tokenDatabase.getTokenIds();
      log.fetchedAllTokenIdsFromDatabase(tokenIds.size());
    } catch (SQLException e) {
      log.errorFetchingAllTokenIdsFromDatabase(e.getMessage(), e);
    }
    return tokenIds;
  }
}
