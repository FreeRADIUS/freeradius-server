/*
 * -*- text -*-
 *
 *   raddb/mods-config/sql/main/mongo/schema-sample.js
 *
 *  Schema for processing radcheck,radreply,radusergroup,radgroupcheck and radgroupreply entries
 */

// Drop
db = db.getSiblingDB("freeradius");
db.dropDatabase();

/*
 * Field: authorize_check_query
 */
db.createCollection("radcheck")

// Load
db.radcheck.insert([
{
    username: 'bob',
    attributes: [
        {
            _id: 0,
            username: 'bob',
            attribute: 'User-Name',
            value: 'bob',
            op: '=='
        },
        {
            _id: 1,
            username: 'bob',
            attribute: 'NAS-Port',
            value: '123',
            op: ':='
        },
        {
            _id: 2,
            username: 'bob',
            attribute: 'Cache-TTL',
            value: '456',
            op: ':='
        }
    ]
}
])

// Query
db.radcheck.aggregate([
{
    $match:{
        'username': 'bob'
    }
},
{
    $unwind: '$attributes'
},
{
    $replaceRoot:{
        newRoot:'$attributes'
    }
}
])


/*
 * Field: authorize_reply_query
 */
db.createCollection("radreply")

// Load
db.radreply.insert([
{
    username: 'bob',
    attributes: [
        {
            _id: 0,
            username: 'bob',
            attribute: 'NAS-IP-Address',
            value: '192.168.250.1',
            op: ':='
        },
        {
            _id: 1,
            username: 'bob',
            attribute: 'Session-Timeout',
            value: '86400',
            op: ':='
        },
        {
            _id: 2,
            username: 'bob',
            attribute: 'Service-Type',
            value: 'Framed-User',
            op: ':='
        }
    ]
}
])

// Query
db.radreply.aggregate([
{
    '$match':{
        'username': 'bob'
    }
},
{
    '$unwind': '$attributes'
},
{
    $replaceRoot:{
        newRoot:'$attributes'
    }
}
])


/*
 * Field: group_membership_query
 */
db.createCollection("radusergroup")

// Load
db.radusergroup.insert([
{
    username: 'bob',
    groupname: 'PLANO_10MB',
    priority: 0
}
])

// Query
db.radusergroup.aggregate([
    {
        "$match": {
            "username": "bob"
        }
    },
    {
        '$project': { 
            _id: 0,
            'groupname': '$groupname'
        }
    }
])


/*
 * Field: authorize_group_check_query
 */
db.createCollection("radgroupcheck")

// Load
db.radgroupcheck.insert([
{
    groupname: 'PLANO_10MB',
    attributes: [
        {
            _id: 0,
            groupname: 'PLANO_10MB',
            attribute: 'Service-Type',
            value: 'Framed-User',
            op: ':='
        },
        {
            _id: 1,
            groupname: 'PLANO_10MB',
            attribute: 'Framed-Protocol',
            value: 'PPP',
            op: ':='
        },
        {
            _id: 2,
            groupname: 'PLANO_10MB',
            attribute: 'IP-Pool.Name',
            value: 'pool_valido',
            op: ':='
        },
    ]
}
])

db.radgroupcheck.aggregate([
{
    '$match': {
        'groupname': 'PLANO_10MB'
    }
},
{
    '$unwind': '$attributes'
},
{
    '$replaceRoot': {
        'newRoot': '$attributes'
    }
}
])

/*
 * Field: authorize_group_reply_query
 */
db.createCollection("radgroupreply")

// Load
db.radgroupreply.insert([
{
    groupname: 'PLANO_10MB',
    attributes: [
        {
            _id: 0,
            groupname: 'PLANO_10MB',
            attribute: 'Acct-Output-Gigawords',
            value: '4096',
            op: ':='
        },
        {
            _id: 1,
            groupname: 'PLANO_10MB',
            attribute: 'Acct-Input-Gigawords',
            value: '4096',
            op: ':='
        },
        {
            _id: 2,
            groupname: 'PLANO_10MB',
            attribute: 'Vendor-Specific.WISPr.Redirection-URL',
            value: 'http://192.168.1.1/captive',
            op: ':='
        },
        {
            _id: 3,
            groupname: 'PLANO_10MB',
            attribute: 'Vendor-Specific.WISPr.Location-ID',
            value: 'CaptiveTapioca',
            op: ':='
        }
    ]
}
])

db.radgroupreply.aggregate([
{
    '$match': {
        'groupname': 'PLANO_10MB'
    }
},
{
    '$unwind': '$attributes'
},
{
    '$replaceRoot': {
        'newRoot': '$attributes'
    }
}
])

/*
 * Accounting
 */
db.createCollection("radacct")
// accounting-on {
// query1
db.radacct.findAndModify({
   "query":{
      "acctstoptime":null,
      "nasipaddress":"127.0.0.1",
      "acctstarttime":{
         "$lt":100
      }
   },
   "update":{
      "$set":{
         "acctstoptime":"100",
         "acctsessiontime":{
            "$subtract":[
               "100",
               "acctstarttime"
            ]
         },
         "acctterminatecause":"NAS-Reboot",
         "class":"0xcafecade",
         "framedipaddress":"10.153.10.1",
         "update_date":{
            "$date":{
               "$numberLong":"1692128889000"
            }
         },
         "start_time":""
      },
      "$push":{
         "events_data":{
            "event_id":"0x930df6959411d02de4a16c0abdc2dbeac0d8d86bb8db39346209837843fe4d41",
            "event_type":"Accounting-On",
            "event_time":"",
            "creation_date":{
               "$date":{
                  "$numberLong":"1692128889000"
               }
            }
         }
      },
      "$setOnInsert":{
         "pool_name":"",
         "closed":false,
         "update_counter":0,
         "creation_date":{
            "$date":{
               "$numberLong":"1692128889000"
            }
         }
      }
   },
   "upsert":true
})

//query2
// db.createCollection("nasreload")
// db.nasreload.findAndModify({
//     {  // find a document with that filter
//         'nasipaddress': %{NAS-IP-Address},
//         'reloadtime': ${....event_timestamp}
//     },
//     "update": {
//         'nasipaddress': %{NAS-IP-Address},
//         'reloadtime': ${....event_timestamp}  
//     },
//     { upsert: true, new: true} // options
// })
