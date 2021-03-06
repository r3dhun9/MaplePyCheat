# # These packets are server to client
# LOGIN
LOGIN_STATUS = 0x00
SERVERLIST = 0x02
CHARLIST = 0x03
SERVER_IP = 0x04
CHAR_NAME_RESPONSE = 0x05
ADD_NEW_CHAR_ENTRY = 0x06
DELETE_CHAR_RESPONSE = 0x07
CHANGE_CHANNEL = 0x08
PING = 0x09
CS_USE = 0x0A
SHEEP_SCORE = 0x143
SHEEP_TEAM  = 0x144
CHANNEL_SELECTED = 0x0D
RELOG_RESPONSE = 0x0F
SECONDPW_ERROR = 0x10
CHOOSE_GENDER = 0x14
GENDER_SET = 0x15
SERVERSTATUS = 0x16
# CwvsContext
MODIFY_INVENTORY_ITEM = 0x1B
UPDATE_INVENTORY_SLOT = 0x1C
UPDATE_STATS = 0x1D
GIVE_BUFF = 0x1E
CANCEL_BUFF = 0x1F
TEMP_STATS = 0x20
TEMP_STATS_RESET = 0x21
UPDATE_SKILLS = 0x22
SKILL_USE_RESULT = 0x23
FAME_RESPONSE = 0x24
SHOW_STATUS_INFO = 0x25
SHOW_NOTES = 0x26
MAP_TRANSFER_RESULT = 0x27
ANTI_MACRO_RESULT = 0x28
# \u6e2c\u8b0a\u6a5f[\u5b8c\u6210]
LP_AntiMacroResult = 0x28
# \u70b8\u5f48\u6e2c\u8b0a\u6a5f[\u5b8c\u6210]
LP_AntiMacroBombResult = 0x29
CLAIM_RESULT = 0x2A
CLAIM_STATUS_CHANGED = 0x2C
SET_TAMING_MOB_INFO = 0x2D
SHOW_QUEST_COMPLETION = 0x2E
ENTRUSTED_SHOP_CHECK_RESULT = 0x2F 
#\u73a9\u5bb6\u96d5\u50cf[\u5b8c\u6210]
PLAYER_NPC = 0x30
USE_SKILL_BOOK = 0x31
FINISH_SORT = 0x33
#\u00a6\u00b3\u00a5i\u00af\u00e0\u00acOFINISH_GATHER = 0x32
FINISH_GATHER = 0x34
CHAR_INFO = 0x36
PARTY_OPERATION = 0x37
#EXPEDITION_OPERATION = 0x36
BUDDYLIST = 0x3A
GUILD_OPERATION = 0x3C
ALLIANCE_OPERATION = 0x3D
SPAWN_PORTAL = 0x3E
SERVERMESSAGE = 0x3F
INCUBATOR_RESULT = 0x40
#PIGMI_REWARD = 0x3E
SHOP_SCANNER_RESULT = 0x41
SHOP_LINK_RESULT = 0x42
MARRIAGE_REQUEST = 0x43
MARRIAGE_RESULT = 0x44
SET_WEEK_EVENT_MESSAGE = 0x48
SET_POTION_DISCOUNT_RATE = 0x49
BRIDE_MOB_CATCH_FAIL = 0x4A
IMITATED_NPC_RESULT = 0x4C
IMITATED_NPC_DATA = 0x4D
LIMITED_NPC_DISABLE_INFO = 0x4E
MONSTERBOOK_ADD = 0x4F
MONSTERBOOK_CHANGE_COVER = 0x50
HOUR_CHANGED = 0x51
MINIMAP_ON_OFF = 0x52
CONSULT_AUTHKEY_UPDATE = 0x53
CLASS_COMPETITION_AUTHKEY_UPDATE = 0x54
WEB_BOARD_AUTHKEY_UPDATE = 0x55
SESSION_VALUE = 0x56
FAIRY_PEND_MSG = 0x57
BONUS_EXP_CHANGED = 0x59
FAMILY_CHART_RESULT = 0x5A
#\u00abH\u00ae\u00a7
FAMILY_INFO_RESULT = 0x5B
#\u00c5\u00e3\u00a5\u00dc\u00b5\u00b2\u00aaG
FAMILY_RESULT = 0x5C
#\u00c1\u00dc\u00bd\u00d0\u00b5\u00a1\u00a4f
FAMILY_JOIN_REQUEST = 0x5D
#\u00b1\u00b5\u00a8\u00fc\u00a9\u00da\u00b5\u00b4\u00a6^\u00b6\u00c7
FAMILY_JOIN_REQUEST_RESULT = 0x5E
#\u00a6\u00a8\u00ac\u00b0\u00be\u00c9\u00aev
FAMILY_JOIN_ACCEPTED = 0x5F
#\u00be\u00c7\u00b0|\u00c5v\u00ad\u00ad
FAMILY_PRIVILEGE_LIST = 0x60
#\u00a6W\u00c1n\u00ab\u00d7
FAMILY_FAMOUS_POINT_INC_RESULT = 0x61
#\u00b5n\u00a4J\u00b5n\u00a5X\u00b4\u00a3\u00bf\u00f4
FAMILY_NOTIFY_LOGIN_OR_LOGOUT = 0x62
FAMILY_SET_PRIVILEGE = 0x63
FAMILY_SUMMON_REQUEST = 0x64
#
LEVEL_UPDATE = 0x65
MARRIAGE_UPDATE = 0x66
JOB_UPDATE = 0x67
SET_BUY_EQUIP_EXT = 0x68
TOP_MSG = 0x69
DATA_CRC_CHECK_FAILED = 0x6A
BBS_OPERATION = 0x6D
FISHING_BOARD_UPDATE = 0x6E
UPDATE_BEANS = 0x6F
DONATE_BEANS = 0x70
AVATAR_MEGA = 0x72
# \u00a5H\u00a4W\u00a7\u00b9\u00a6\u00a8
# \u00b3o\u00a4T\u00ad\u00d3\u00a5\u00bc\u00aa\u00be
EXP_CHAIR_MESSAGE = 0x77
SELECT_SLED = 0x79
USE_TREASUER_CHEST = 0x71
SKILL_MACRO = 0x7F
SET_FIELD = 0x80
SET_ITC = 0x81
SET_CASH_SHOP = 0x82
SET_MAP_OBJECT_VISIBLE = 0x84
CLEAR_BACK_EFFECT = 0x85
MAP_BLOCKED = 0x86
SERVER_BLOCKED = 0x87
SHOW_EQUIP_EFFECT = 0x88
MULTICHAT = 0x89
WHISPER = 0x8A
BOSS_ENV = 0x8C
MOVE_ENV = 0x8D
#UPDATE_ENV = 0x88
#MAP_EFFECT = 0x88
CASH_SONG = 0x8E
GM_EFFECT = 0x8F
OX_QUIZ = 0x90
GMEVENT_INSTRUCTIONS = 0x91
CLOCK = 0x92
BOAT_EFFECT = 0x93
BOAT_PACKET = 0x94
STOP_CLOCK = 0x98
PYRAMID_UPDATE = 0x9B
PYRAMID_RESULT = 0x9C
MOVE_PLATFORM = 0x96
SPAWN_PLAYER = 0xA1
REMOVE_PLAYER_FROM_MAP = 0xA2
CHATTEXT = 0xA3
CHALKBOARD = 0xA4
UPDATE_CHAR_BOX = 0xA5
SHOW_SCROLL_EFFECT = 0xA7
#SHOW_POTENTIAL_EFFECT = 0xB0
#SHOW_POTENTIAL_RESET = 0xB1
FISHING_CAUGHT = 0xA8
#PAMS_SONG = 0xB6
#FOLLOW_EFFECT = 0xB7
#================================
# CUserPool::OnUserPetPacket \u958b\u59cb
#================================ 
# \u53ec\u559a\u5bf5\u7269 LP_PetActivated
SPAWN_PET = 0xAE
# \u5bf5\u7269\u79fb\u52d5 LP_PetMove
MOVE_PET = 0xB1
# \u5bf5\u7269\u8aaa\u8a71 LP_PetActionSpeak
PET_CHAT = 0xB2
# \u8b8a\u66f4\u5bf5\u7269\u540d\u7a31 LP_PetNameChanged
PET_NAMECHANGE = 0xB3
# \u5bf5\u7269\u4f8b\u5916\u6e05\u55ae LP_PetLoadExceptionList
PET_LOAD_EXCEPTIONLIST = 0xB4
# \u5bf5\u7269\u6307\u4ee4 LP_PetActionCommand
PET_COMMAND = 0xB5
#================================
# CUser::OnSummonedPacket \u958b\u59cb
#================================ 
# \u53ec\u559a\u7378\u9032\u5834 LP_SummonedEnterField
SPAWN_SUMMON = 0xB6
# \u53ec\u559a\u7378\u96e2\u5834 LP_SummonedLeaveField
REMOVE_SUMMON = 0xB7
# \u53ec\u559a\u7378\u79fb\u52d5 LP_SummonedMove
MOVE_SUMMON = 0xB8
# \u53ec\u559a\u7378\u653b\u64ca LP_SummonedAttack
SUMMON_ATTACK = 0xB9
# \u62db\u559a\u7378\u6280\u80fd LP_SummonedSkill
SUMMON_SKILL = 0xBA
# \u62db\u559a\u7378\u53d7\u50b7 LP_SummonedHPTagUpdate
DAMAGE_SUMMON = 0xBB
DRAGON_SPAWN = 0xBC
DRAGON_MOVE = 0xBD
DRAGON_REMOVE = 0xBE
#================================
# CUserPool::OnUserRemotePacket \u958b\u59cb
#================================ 
# \u73a9\u5bb6\u79fb\u52d5 LP_UserMove
MOVE_PLAYER = 0xC0
CLOSE_RANGE_ATTACK = 0xC1
RANGED_ATTACK = 0xC2
MAGIC_ATTACK = 0xC3
ENERGY_ATTACK = 0xC4
SKILL_EFFECT = 0xC5
CANCEL_SKILL_EFFECT = 0xC6
DAMAGE_PLAYER = 0xC7
FACIAL_EXPRESSION = 0xC8
SHOW_ITEM_EFFECT = 0xC9
SHOW_CHAIR = 0xCC
UPDATE_CHAR_LOOK = 0xCD
SHOW_FOREIGN_EFFECT = 0xCE
GIVE_FOREIGN_BUFF = 0xCF
CANCEL_FOREIGN_BUFF = 0xD0
UPDATE_PARTYMEMBER_HP = 0xD1
GUILD_NAME_CHANGED = 0xD2
GUILD_MARK_CHANGED = 0xD3
CANCEL_CHAIR = 0xD5
SHOW_ITEM_GAIN_INCHAT = 0xD7
CURRENT_MAP_WARP = 0xD8
MESOBAG_SUCCESS = 0xDA
MESOBAG_FAILURE = 0xDB
UPDATE_QUEST_INFO = 0xDC
PET_FLAG_CHANGE = 0xDE
PLAYER_HINT = 0xDF
REPAIR_WINDOW = 0xE5
CYGNUS_INTRO_LOCK = 0xE7
CYGNUS_INTRO_DISABLE_UI = 0xE8
SUMMON_HINT = 0xE9
SUMMON_HINT_MSG = 0xEA
# \u72c2\u72fc\u52c7\u58eb\u9023\u64ca
ARAN_COMBO = 0xEB
GAME_POLL_REPLY = 0xEE
#FOLLOW_MESSAGE = 0xFD
#FOLLOW_MOVE = 0x101
#FOLLOW_MSG = 0x102
#GAME_POLL_QUESTION = 0x103
COOLDOWN = 0xF7
SPAWN_MONSTER = 0xF9
KILL_MONSTER = 0xFA
SPAWN_MONSTER_CONTROL = 0xFB
MOVE_MONSTER = 0xFC
MOVE_MONSTER_RESPONSE = 0xFD
APPLY_MONSTER_STATUS = 0xFF
CANCEL_MONSTER_STATUS = 0x100
MOB_TO_MOB_DAMAGE = 0x102
DAMAGE_MONSTER = 0x103
SHOW_MONSTER_HP = 0x107
SHOW_MAGNET = 0x108
CATCH_MONSTER = 0x109
MOB_SPEAKING = 0x10A
MONSTER_PROPERTIES = 0x10C
TALK_MONSTER = 0x10E
REMOVE_TALK_MONSTER = 0x10F
NPC_USE_SCRIPT = 0x101
SPAWN_NPC = 0x113
REMOVE_NPC = 0x114
SPAWN_NPC_REQUEST_CONTROLLER = 0x115
NPC_ACTION = 0x116
SPAWN_HIRED_MERCHANT = 0x11D
DESTROY_HIRED_MERCHANT = 0x11E
UPDATE_HIRED_MERCHANT = 0x120
DROP_ITEM_FROM_MAPOBJECT = 0x121
REMOVE_ITEM_FROM_MAP = 0x122
SPAWN_KITE_ERROR = 0x123
DESTROY_KITE = 0x125
SPAWN_KITE = 0x124
SPAWN_MIST = 0x126
REMOVE_MIST = 0x127
SPAWN_DOOR = 0x128
REMOVE_DOOR = 0x129
REACTOR_HIT = 0x12D
REACTOR_SPAWN = 0x12F
REACTOR_DESTROY = 0x130
ROLL_SNOWBALL = 0x131
HIT_SNOWBALL = 0x132
SNOWBALL_MESSAGE = 0x133
LEFT_KNOCK_BACK = 0x134
HIT_COCONUT = 0x135
COCONUT_SCORE = 0x136
MONSTER_CARNIVAL_START = 0x139
MONSTER_CARNIVAL_OBTAINED_CP = 0x13A
MONSTER_CARNIVAL_PARTY_CP = 0x13B
MONSTER_CARNIVAL_SUMMON = 0x13C
MONSTER_CARNIVAL_DIED = 0x13E
CHAOS_HORNTAIL_SHRINE = 0x142
CHAOS_ZAKUM_SHRINE = 0x143
HORNTAIL_SHRINE = 0x144
ZAKUM_SHRINE = 0x145
ENGLISH_QUIZ = 0x146
#\u96ea\u6a47\u904a\u6232
#310
#302
#303
#304
#305
#306
#307
#308
#309
#311
#312
NPC_TALK = 0x156
OPEN_NPC_SHOP = 0x157
CONFIRM_SHOP_TRANSACTION = 0x158
OPEN_STORAGE = 0x141
MERCH_ITEM_MSG = 0x142
MERCH_ITEM_STORE = 0x143
RPS_GAME = 0x144
MESSENGER = 0x145
PLAYER_INTERACTION = 0x146
# \u5c0f\u92fc\u73e0\u5c01\u5305
LP_BeansTips = 0x16C
LP_BeanGameShow = 0x16D
LP_BeanGameShoot = 0x16E
DUEY = 0x155
CS_WEB = 0x170
CS_UPDATE = 0x171
CS_OPERATION = 0x172
XMAS_SURPRISE = 0x161
CS_ACC = 0x17A
KEYMAP = 0x17E
PET_AUTO_HP = 0x17F
PET_AUTO_MP = 0x180
GET_MTS_TOKENS = 0x169
MTS_OPERATION = 0x16A
#not confirmed
BLOCK_PORTAL = 0x81
ARIANT_SCOREBOARD = 0x99
ARIANT_THING = 0xF2
ARIANT_PQ_START = 0x141
VICIOUS_HAMMER = 0x17A
#not updated
REPORT_PLAYER_MSG = 0x999
NPC_CONFIRM = 0x999