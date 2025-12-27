import datetime

# get the current time in GMT
now = datetime.datetime.utcnow()
# format the time as a string in the desired format
formatted_time = now.strftime("%a, %d %b %Y %H:%M:%S %Z")

RESPONSE_HEADER = (
    b"""HTTP/2 200 OK
Content-Type: application/json; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
Last-Modified: """
    + formatted_time.encode()
    + b"""
x-amz-server-side-encryption: AES256
x-amz-version-id: tZRusENvTn.kue_2SfbTw8S9WaZIc4FN
Server: AmazonS3
Content-Encoding: gzip
Date: Wed, 22 Feb 2023 19:45:38 GMT
ETag: W/"3ac53e7efa1a273cabdb23ea4acb0868"
Vary: Acept-Encoding
X-Cache: Hit from cloudfront
Via: 1.1 2cbf148f6c14a1a6f56400dc9dc76f2a.cloudfront.net (CloudFront)
X-Amz-Cf-Pop: ARN56-P2
X-Amz-Cf-Id: 7Xsj6-K_NKWYdZLKuf6zKCGn-7m7vRbFF4rBLQYr5BYjalphT9-YZg==
Age: 2943

"""
)

ENDPOINTS = [
    "data/config/MazeConfig.json",
    "data/config/pvp_reward.json",
    "data/config/shop_in_app_purchase.json",
    "data/config/pve_season.json",
    "data/config/dailySeasonData.json",
    "data/config/activity_christmas.json",
    "data/config/farm_pvp_rank_reward.json",
    "data/config/game_choice_box.json",
    "data/config/farm_pvp_season.json",
    "data/config/MazeLine.json",
    "data/config/pve_stage_rank_reward.json",
    "data/config/pvp_season.json",
    "data/config/pve_week_rank_reward.json",
    "data/config/game_config.json",
    "data/config/game_activity_treasure.json",
    "data/config/worldcup_matches.json",
    "data/config/battlePassConfigData.json",
]
