var data = {
    "actions": {
        "rule": [
            {
                "name": "app-Add",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "appName"
                    }
                ]
            },
            {
                "name": "app-Remove",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "appName"
                    }
                ]
            },
            {
                "name": "app-Remove-Force-Any",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "appName"
                    }
                ]
            },
            {
                "name": "app-Set-Any",
                "help": null,
                "args": false
            },
            {
                "name": "biDirNat-Split",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "-DST",
                        "name": "suffix"
                    }
                ]
            },
            {
                "name": "clone",
                "help": null,
                "args": [
                    {
                        "type": "bool",
                        "default": "yes",
                        "name": "before"
                    },
                    {
                        "type": "string",
                        "default": "-cloned",
                        "name": "suffix"
                    }
                ]
            },
            {
                "name": "cloneForAppOverride",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "applicationName"
                    },
                    {
                        "type": "string",
                        "default": "*sameAsInRule*",
                        "name": "restrictToListOfServices"
                    }
                ]
            },
            {
                "name": "copy",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "location"
                    },
                    {
                        "type": "string",
                        "default": "pre",
                        "choices": [
                            "pre",
                            "post"
                        ],
                        "name": "preORpost"
                    }
                ]
            },
            {
                "name": "delete",
                "help": null,
                "args": false
            },
            {
                "name": "description-Append",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "text"
                    }
                ]
            },
            {
                "name": "disabled-Set",
                "help": null,
                "args": [
                    {
                        "type": "bool",
                        "default": "yes",
                        "name": "trueOrFalse"
                    }
                ]
            },
            {
                "name": "disabled-Set-FastAPI",
                "help": null,
                "args": [
                    {
                        "type": "bool",
                        "default": "yes",
                        "name": "trueOrFalse"
                    }
                ]
            },
            {
                "name": "display",
                "help": null,
                "args": false
            },
            {
                "name": "dst-Add",
                "help": "adds&nbspan&nbspobject&nbspin&nbspthe&nbsp'DESTINATION'&nbspfield&nbspof&nbspa&nbsprule,&nbspif&nbspthat&nbspfield&nbspwas&nbspset&nbspto&nbsp'ANY'&nbspit&nbspwill&nbspthen&nbspbe&nbspreplaced&nbspby&nbspthis&nbspobject.",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "objName"
                    }
                ]
            },
            {
                "name": "dst-Negate-Set",
                "help": "manages&nbspDestination&nbspNegation&nbspenablement",
                "args": [
                    {
                        "type": "bool",
                        "default": "*nodefault*",
                        "name": "YESorNO"
                    }
                ]
            },
            {
                "name": "dst-Remove",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "objName"
                    }
                ]
            },
            {
                "name": "dst-Remove-Force-Any",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "objName"
                    }
                ]
            },
            {
                "name": "dst-set-Any",
                "help": null,
                "args": false
            },
            {
                "name": "enabled-Set",
                "help": null,
                "args": [
                    {
                        "type": "bool",
                        "default": "yes",
                        "name": "trueOrFalse"
                    }
                ]
            },
            {
                "name": "enabled-Set-FastAPI",
                "help": null,
                "args": [
                    {
                        "type": "bool",
                        "default": "yes",
                        "name": "trueOrFalse"
                    }
                ]
            },
            {
                "name": "exportToExcel",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "filename"
                    }
                ]
            },
            {
                "name": "from-Add",
                "help": "Adds&nbspa&nbspzone&nbspin&nbspthe&nbsp'FROM'&nbspfield&nbspof&nbspa&nbsprule.&nbspIf&nbspFROM&nbspwas&nbspset&nbspto&nbspANY&nbspthen&nbspit&nbspwill&nbspbe&nbspreplaced&nbspby&nbspzone&nbspin&nbspargument.Zone&nbspmust&nbspbe&nbspexisting&nbspalready&nbspor&nbspscript&nbspwill&nbspout&nbspan&nbsperror.&nbspUse&nbspaction&nbspfrom-add-force&nbspif&nbspyou&nbspwant&nbspto&nbspadd&nbspa&nbspzone&nbspthat&nbspdoes&nbspnot&nbspnot&nbspexist.",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "zoneName"
                    }
                ]
            },
            {
                "name": "from-Add-Force",
                "help": "Adds&nbspa&nbspzone&nbspin&nbspthe&nbsp'FROM'&nbspfield&nbspof&nbspa&nbsprule.&nbspIf&nbspFROM&nbspwas&nbspset&nbspto&nbspANY&nbspthen&nbspit&nbspwill&nbspbe&nbspreplaced&nbspby&nbspzone&nbspin&nbspargument.",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "zoneName"
                    }
                ]
            },
            {
                "name": "from-calculate-zones",
                "help": "This&nbspAction&nbspwill&nbspuse&nbsprouting&nbsptables&nbspto&nbspresolve&nbspzones.&nbspWhen&nbspthe&nbspprogram&nbspcannot&nbspfind&nbspall&nbspparameters&nbspby&nbspitself&nbsp(like&nbspvsys&nbspor&nbsptemplate&nbspname&nbspyou&nbspwill&nbsphave&nbspti&nbspmanually&nbspprovide&nbspthem.<br><br>Usage&nbspexamples:<br><br>&nbsp&nbsp&nbsp&nbsp-&nbspxxx-calculate-zones<br>&nbsp&nbsp&nbsp&nbsp-&nbspxxx-calculate-zones:replace<br>&nbsp&nbsp&nbsp&nbsp-&nbspxxx-calculate-zones:append,vr1<br>&nbsp&nbsp&nbsp&nbsp-&nbspxxx-calculate-zones:replace,vr3,api@0011C890C,vsys1<br>&nbsp&nbsp&nbsp&nbsp-&nbspxxx-calculate-zones:show,vr5,Datacenter_template<br>&nbsp&nbsp&nbsp&nbsp-&nbspxxx-calculate-zones:replace,vr3,file@firewall.xml,vsys1<br>",
                "args": [
                    {
                        "type": "string",
                        "default": "append",
                        "choices": [
                            "replace",
                            "append",
                            "show"
                        ],
                        "help": "Will determine what to do with resolved zones : show them, replace them in the rule or only append them (removes none but adds missing ones)",
                        "name": "mode"
                    },
                    {
                        "type": "string",
                        "default": "*autodetermine*",
                        "help": "Can optionally be provided if script cannot find which virtualRouter it should be using (ie: there are several VR in same VSYS)",
                        "name": "virtualRouter"
                    },
                    {
                        "type": "string",
                        "default": "*notPanorama*",
                        "help": "When you are using Panorama then 1 or more templates could apply to a DeviceGroup, in such a case you may want to specify which Template name to use.\nBeware that if the Template is overriden or if you are not using Templates then you will want load firewall config in lieu of specifying a template. \nFor this, give value 'api@XXXXX' where XXXXX is serial number of the Firewall device number you want to use to calculate zones.\nIf you don't want to use API but have firewall config file on your computer you can then specify file@\/folderXYZ\/config.xml.",
                        "name": "template"
                    },
                    {
                        "type": "string",
                        "default": "*autodetermine*",
                        "help": "specify vsys when script cannot autodetermine it or when you when to manually override",
                        "name": "vsys"
                    }
                ]
            },
            {
                "name": "from-Remove",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "zoneName"
                    }
                ]
            },
            {
                "name": "from-Remove-Force-Any",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "zoneName"
                    }
                ]
            },
            {
                "name": "from-Replace",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "zoneToReplaceName"
                    },
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "zoneForReplacementName"
                    },
                    {
                        "type": "boolean",
                        "default": "no",
                        "name": "force"
                    }
                ]
            },
            {
                "name": "from-Set-Any",
                "help": null,
                "args": false
            },
            {
                "name": "invertPreAndPost",
                "help": null,
                "args": false
            },
            {
                "name": "logEnd-Disable",
                "help": "disables&nbsp'log&nbspat&nbspend'&nbspin&nbspa&nbspsecurity&nbsprule.",
                "args": false
            },
            {
                "name": "logend-Disable-FastAPI",
                "help": "disables&nbsp'log&nbspat&nbspend'&nbspin&nbspa&nbspsecurity&nbsprule.<br>'FastAPI'&nbspallows&nbspAPI&nbspcommands&nbspto&nbspbe&nbspsent&nbspall&nbspat&nbsponce&nbspinstead&nbspof&nbspa&nbspsingle&nbspcall&nbspper&nbsprule,&nbspallowing&nbspmuch&nbspfaster&nbspexecution&nbsptime.",
                "args": false
            },
            {
                "name": "logEnd-Enable",
                "help": "enables&nbsp'log&nbspat&nbspend'&nbspin&nbspa&nbspsecurity&nbsprule.",
                "args": false
            },
            {
                "name": "logend-Enable-FastAPI",
                "help": "enables&nbsp'log&nbspat&nbspend'&nbspin&nbspa&nbspsecurity&nbsprule.<br>'FastAPI'&nbspallows&nbspAPI&nbspcommands&nbspto&nbspbe&nbspsent&nbspall&nbspat&nbsponce&nbspinstead&nbspof&nbspa&nbspsingle&nbspcall&nbspper&nbsprule,&nbspallowing&nbspmuch&nbspfaster&nbspexecution&nbsptime.",
                "args": false
            },
            {
                "name": "logSetting-set",
                "help": "Sets&nbsplog&nbspsetting\/forwarding&nbspprofile&nbspof&nbspa&nbspSecurity&nbsprule&nbspto&nbspthe&nbspvalue&nbspspecified.",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "profName"
                    }
                ]
            },
            {
                "name": "logStart-Disable",
                "help": "enables&nbsp\"log&nbspat&nbspstart\"&nbspin&nbspa&nbspsecurity&nbsprule",
                "args": false
            },
            {
                "name": "logStart-Disable-FastAPI",
                "help": "disables&nbsp'log&nbspat&nbspstart'&nbspin&nbspa&nbspsecurity&nbsprule.<br>'FastAPI'&nbspallows&nbspAPI&nbspcommands&nbspto&nbspbe&nbspsent&nbspall&nbspat&nbsponce&nbspinstead&nbspof&nbspa&nbspsingle&nbspcall&nbspper&nbsprule,&nbspallowing&nbspmuch&nbspfaster&nbspexecution&nbsptime.",
                "args": false
            },
            {
                "name": "logStart-Enable",
                "help": "disables&nbsp\"log&nbspat&nbspstart\"&nbspin&nbspa&nbspsecurity&nbsprule",
                "args": false
            },
            {
                "name": "logStart-Enable-FastAPI",
                "help": "enables&nbsp'log&nbspat&nbspstart'&nbspin&nbspa&nbspsecurity&nbsprule.<br>'FastAPI'&nbspallows&nbspAPI&nbspcommands&nbspto&nbspbe&nbspsent&nbspall&nbspat&nbsponce&nbspinstead&nbspof&nbspa&nbspsingle&nbspcall&nbspper&nbsprule,&nbspallowing&nbspmuch&nbspfaster&nbspexecution&nbsptime.",
                "args": false
            },
            {
                "name": "move",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "location"
                    },
                    {
                        "type": "string",
                        "default": "pre",
                        "choices": [
                            "pre",
                            "post"
                        ],
                        "name": "preORpost"
                    }
                ]
            },
            {
                "name": "name-Append",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "text"
                    }
                ]
            },
            {
                "name": "name-Prepend",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "text"
                    }
                ]
            },
            {
                "name": "ruleType-Change",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "text"
                    }
                ]
            },
            {
                "name": "securityProfile-Group-Set",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "profName"
                    }
                ]
            },
            {
                "name": "securityProfile-Group-Set-FastAPI",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "profName"
                    }
                ]
            },
            {
                "name": "securityProfile-Remove",
                "help": null,
                "args": false
            },
            {
                "name": "service-Add",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "svcName"
                    }
                ]
            },
            {
                "name": "service-Remove",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "svcName"
                    }
                ]
            },
            {
                "name": "service-Remove-Force-Any",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "svcName"
                    }
                ]
            },
            {
                "name": "service-Set-Any",
                "help": null,
                "args": false
            },
            {
                "name": "service-Set-AppDefault",
                "help": null,
                "args": false
            },
            {
                "name": "src-Add",
                "help": "adds&nbspan&nbspobject&nbspin&nbspthe&nbsp'SOURCE'&nbspfield&nbspof&nbspa&nbsprule,&nbspif&nbspthat&nbspfield&nbspwas&nbspset&nbspto&nbsp'ANY'&nbspit&nbspwill&nbspthen&nbspbe&nbspreplaced&nbspby&nbspthis&nbspobject.",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "objName"
                    }
                ]
            },
            {
                "name": "src-Negate-Set",
                "help": "manages&nbspSource&nbspNegation&nbspenablement",
                "args": [
                    {
                        "type": "bool",
                        "default": "*nodefault*",
                        "name": "YESorNO"
                    }
                ]
            },
            {
                "name": "src-Remove",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "objName"
                    }
                ]
            },
            {
                "name": "src-Remove-Force-Any",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "objName"
                    }
                ]
            },
            {
                "name": "src-set-Any",
                "help": null,
                "args": false
            },
            {
                "name": "tag-Add",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "tagName"
                    }
                ]
            },
            {
                "name": "tag-Add-Force",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "tagName"
                    }
                ]
            },
            {
                "name": "tag-Remove",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "tagName"
                    }
                ]
            },
            {
                "name": "tag-Remove-All",
                "help": null,
                "args": false
            },
            {
                "name": "tag-Remove-Regex",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "regex"
                    }
                ]
            },
            {
                "name": "target-Add-Device",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "serial"
                    },
                    {
                        "type": "string",
                        "default": "*NULL*",
                        "name": "vsys"
                    }
                ]
            },
            {
                "name": "target-Negate-Set",
                "help": null,
                "args": [
                    {
                        "type": "bool",
                        "default": "*nodefault*",
                        "name": "trueOrFalse"
                    }
                ]
            },
            {
                "name": "target-Remove-Device",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "serial"
                    },
                    {
                        "type": "string",
                        "default": "*NULL*",
                        "name": "vsys"
                    }
                ]
            },
            {
                "name": "target-Set-Any",
                "help": null,
                "args": false
            },
            {
                "name": "to-Add",
                "help": "Adds&nbspa&nbspzone&nbspin&nbspthe&nbsp'TO'&nbspfield&nbspof&nbspa&nbsprule.&nbspIf&nbspTO&nbspwas&nbspset&nbspto&nbspANY&nbspthen&nbspit&nbspwill&nbspbe&nbspreplaced&nbspby&nbspzone&nbspin&nbspargument.Zone&nbspmust&nbspbe&nbspexisting&nbspalready&nbspor&nbspscript&nbspwill&nbspout&nbspan&nbsperror.&nbspUse&nbspaction&nbspto-add-force&nbspif&nbspyou&nbspwant&nbspto&nbspadd&nbspa&nbspzone&nbspthat&nbspdoes&nbspnot&nbspnot&nbspexist.",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "zoneName"
                    }
                ]
            },
            {
                "name": "to-Add-Force",
                "help": "Adds&nbspa&nbspzone&nbspin&nbspthe&nbsp'FROM'&nbspfield&nbspof&nbspa&nbsprule.&nbspIf&nbspFROM&nbspwas&nbspset&nbspto&nbspANY&nbspthen&nbspit&nbspwill&nbspbe&nbspreplaced&nbspby&nbspzone&nbspin&nbspargument.",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "zoneName"
                    }
                ]
            },
            {
                "name": "to-calculate-zones",
                "help": "This&nbspAction&nbspwill&nbspuse&nbsprouting&nbsptables&nbspto&nbspresolve&nbspzones.&nbspWhen&nbspthe&nbspprogram&nbspcannot&nbspfind&nbspall&nbspparameters&nbspby&nbspitself&nbsp(like&nbspvsys&nbspor&nbsptemplate&nbspname&nbspyou&nbspwill&nbsphave&nbspti&nbspmanually&nbspprovide&nbspthem.<br><br>Usage&nbspexamples:<br><br>&nbsp&nbsp&nbsp&nbsp-&nbspxxx-calculate-zones<br>&nbsp&nbsp&nbsp&nbsp-&nbspxxx-calculate-zones:replace<br>&nbsp&nbsp&nbsp&nbsp-&nbspxxx-calculate-zones:append,vr1<br>&nbsp&nbsp&nbsp&nbsp-&nbspxxx-calculate-zones:replace,vr3,api@0011C890C,vsys1<br>&nbsp&nbsp&nbsp&nbsp-&nbspxxx-calculate-zones:show,vr5,Datacenter_template<br>&nbsp&nbsp&nbsp&nbsp-&nbspxxx-calculate-zones:replace,vr3,file@firewall.xml,vsys1<br>",
                "args": [
                    {
                        "type": "string",
                        "default": "append",
                        "choices": [
                            "replace",
                            "append",
                            "show"
                        ],
                        "help": "Will determine what to do with resolved zones : show them, replace them in the rule or only append them (removes none but adds missing ones)",
                        "name": "mode"
                    },
                    {
                        "type": "string",
                        "default": "*autodetermine*",
                        "help": "Can optionally be provided if script cannot find which virtualRouter it should be using (ie: there are several VR in same VSYS)",
                        "name": "virtualRouter"
                    },
                    {
                        "type": "string",
                        "default": "*notPanorama*",
                        "help": "When you are using Panorama then 1 or more templates could apply to a DeviceGroup, in such a case you may want to specify which Template name to use.\nBeware that if the Template is overriden or if you are not using Templates then you will want load firewall config in lieu of specifying a template. \nFor this, give value 'api@XXXXX' where XXXXX is serial number of the Firewall device number you want to use to calculate zones.\nIf you don't want to use API but have firewall config file on your computer you can then specify file@\/folderXYZ\/config.xml.",
                        "name": "template"
                    },
                    {
                        "type": "string",
                        "default": "*autodetermine*",
                        "help": "specify vsys when script cannot autodetermine it or when you when to manually override",
                        "name": "vsys"
                    }
                ]
            },
            {
                "name": "to-Remove",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "zoneName"
                    }
                ]
            },
            {
                "name": "to-Remove-Force-Any",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "zoneName"
                    }
                ]
            },
            {
                "name": "to-Replace",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "zoneToReplaceName"
                    },
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "zoneForReplacementName"
                    },
                    {
                        "type": "boolean",
                        "default": "no",
                        "name": "force"
                    }
                ]
            },
            {
                "name": "to-Set-Any",
                "help": null,
                "args": false
            }
        ]
    }
};