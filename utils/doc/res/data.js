var data = {
    "actions": {
        "rule": [
            {
                "name": "app-Add",
                "help": null,
                "args": [
                    {
                        "type": "pipeSeparatedList",
                        "subtype": "string",
                        "default": "*nodefault*",
                        "help": "pipe(|) separated list of additional field to include in the report. The following is available:\n  - ResolveAddressSummary : fields with address objects will be resolved to IP addressed and summarized in a new column)\n",
                        "name": "appName"
                    }
                ]
            },
            {
                "name": "app-Add-Force",
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
                "help": "This&nbspaction&nbspwill&nbsptake&nbspa&nbspSecurity&nbsprule&nbspand&nbspclone&nbspit&nbspas&nbspan&nbspApp-Override&nbsprule.&nbspBy&nbspdefault&nbspall&nbspservices&nbspspecified&nbspin&nbspthe&nbsprule&nbspwill&nbspalso&nbspbe&nbspin&nbspthe&nbspAppOverride&nbsprule.",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "specify the application to put in the resulting App-Override rule",
                        "name": "applicationName"
                    },
                    {
                        "type": "string",
                        "default": "*sameAsInRule*",
                        "help": "you can limit which services will be included in the AppOverride rule by providing a #-separated list or a subquery prefixed with a @:\n  - svc1#svc2#svc3... : #-separated list\n  - @subquery1 : script will look for subquery1 filter which you have to provide as an additional argument to the script (ie: 'subquery1=(name eq tcp-50-web)')",
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
                    },
                    {
                        "type": "bool",
                        "default": "no",
                        "name": "newline"
                    }
                ]
            },
            {
                "name": "description-Prepend",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "text"
                    },
                    {
                        "type": "bool",
                        "default": "no",
                        "name": "newline"
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
                "name": "dsri-Set",
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
                "name": "dsri-Set-FastAPI",
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
                "name": "dst-Remove-Objects-Matching-Filter",
                "help": "this&nbspaction&nbspwill&nbspgo&nbspthrough&nbspall&nbspobjects&nbspand&nbspsee&nbspif&nbspthey&nbspmatch&nbspthe&nbspquery&nbspyou&nbspinput&nbspand&nbspthen&nbspremove&nbspthem&nbspif&nbspit's&nbspthe&nbspcase.",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "specify the query that will be used to filter the objects to be removed",
                        "name": "filterName"
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
                    },
                    {
                        "type": "pipeSeparatedList",
                        "subtype": "string",
                        "default": "*NONE*",
                        "choices": [
                            "ResolveAddressSummary",
                            "ResolveServiceSummary"
                        ],
                        "help": "pipe(|) separated list of additional field to include in the report. The following is available:\n  - ResolveAddressSummary : fields with address objects will be resolved to IP addressed and summarized in a new column)\n  - ResolveServiceSummary : fields with service objects will be resolved to their value and summarized in a new column)\n",
                        "name": "additionalFields"
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
                            "show",
                            "unneeded-tag-add"
                        ],
                        "help": "Will determine what to do with resolved zones : show them, replace them in the rule , only append them (removes none but adds missing ones) or tag-add for unneeded zones",
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
                        "type": "bool",
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
                "name": "logSetting-disable",
                "help": "Remove&nbsplog&nbspsetting\/forwarding&nbspprofile&nbspof&nbspa&nbspSecurity&nbsprule&nbspif&nbspany.",
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
                "name": "name-removePrefix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "prefix"
                    }
                ]
            },
            {
                "name": "name-removeSuffix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "suffix"
                    }
                ]
            },
            {
                "name": "name-Rename",
                "help": "",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "This string is used to compose a name. You can use the following aliases :\n  - $$current.name$$ : current name of the object\n  - $$sequential.number$$ : sequential number - starting with 1\n",
                        "name": "stringFormula"
                    }
                ]
            },
            {
                "name": "position-Move-After",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "rulename"
                    }
                ]
            },
            {
                "name": "position-Move-Before",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "rulename"
                    }
                ]
            },
            {
                "name": "position-Move-to-Bottom",
                "help": null,
                "args": false
            },
            {
                "name": "position-Move-to-Top",
                "help": null,
                "args": false
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
                "name": "securityProfile-Profile-Set",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "choices": [
                            "virus",
                            "vulnerability",
                            "url-filtering",
                            "data-filtering",
                            "file-blocking",
                            "spyware",
                            "wildfire"
                        ],
                        "name": "type"
                    },
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
                "name": "src-Remove-Objects-Matching-Filter",
                "help": "this&nbspaction&nbspwill&nbspgo&nbspthrough&nbspall&nbspobjects&nbspand&nbspsee&nbspif&nbspthey&nbspmatch&nbspthe&nbspquery&nbspyou&nbspinput&nbspand&nbspthen&nbspremove&nbspthem&nbspif&nbspit's&nbspthe&nbspcase.",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "specify the query that will be used to filter the objects to be removed",
                        "name": "filterName"
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
                    },
                    {
                        "type": "string",
                        "default": "none",
                        "name": "tagColor"
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
                        "help": "if target firewall is single VSYS you should ignore this argument, otherwise just input it",
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
                            "show",
                            "unneeded-tag-add"
                        ],
                        "help": "Will determine what to do with resolved zones : show them, replace them in the rule , only append them (removes none but adds missing ones) or tag-add for unneeded zones",
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
                        "type": "bool",
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
        ],
        "address": [
            {
                "name": "add-member",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "addressobjectname"
                    }
                ]
            },
            {
                "name": "addObjectWhereUsed",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "objectName"
                    },
                    {
                        "type": "bool",
                        "default": false,
                        "name": "skipNatRules"
                    }
                ]
            },
            {
                "name": "delete",
                "help": null,
                "args": false
            },
            {
                "name": "delete-Force",
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
                "name": "display",
                "help": null,
                "args": false
            },
            {
                "name": "displayReferences",
                "help": null,
                "args": false
            },
            {
                "name": "exportToExcel",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "filename"
                    },
                    {
                        "type": "pipeSeparatedList",
                        "subtype": "string",
                        "default": "*NONE*",
                        "choices": [
                            "WhereUsed",
                            "UsedInLocation",
                            "ResolveIP",
                            "NestedMembers"
                        ],
                        "help": "pipe(|) separated list of additional fields (ie: Arg1|Arg2|Arg3...) to include in the report. The following is available:\n  - NestedMembers: lists all members, even the ones that may be included in nested groups\n  - ResolveIP\n  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n  - WhereUsed : list places where object is used (rules, groups ...)\n",
                        "name": "additionalFields"
                    }
                ]
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
                        "default": "skipIfConflict",
                        "choices": [
                            "skipIfConflict",
                            "removeIfMatch",
                            "removeIfNumericalMatch"
                        ],
                        "name": "mode"
                    }
                ]
            },
            {
                "name": "name-addPrefix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "prefix"
                    }
                ]
            },
            {
                "name": "name-addSuffix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "suffix"
                    }
                ]
            },
            {
                "name": "name-removePrefix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "prefix"
                    }
                ]
            },
            {
                "name": "name-removeSuffix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "suffix"
                    }
                ]
            },
            {
                "name": "name-Rename",
                "help": "",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "This string is used to compose a name. You can use the following aliases :\n  - $$current.name$$ : current name of the object\n  - $$netmask$$ : netmask\n  - $$netmask.blank32$$ : netmask or nothing if 32\n  - $$reverse-dns$$ : value truncated of netmask if any\n  - $$value$$ : value of the object\n  - $$value.no-netmask$$ : value truncated of netmask if any\n",
                        "name": "stringFormula"
                    }
                ]
            },
            {
                "name": "removeWhereUsed",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "delete",
                        "choices": [
                            "delete",
                            "disable",
                            "setAny"
                        ],
                        "name": "actionIfLastMemberInRule"
                    }
                ]
            },
            {
                "name": "replace-IP-by-MT-like-Object",
                "help": null,
                "args": false
            },
            {
                "name": "replaceByMembersAndDelete",
                "help": null,
                "args": false
            },
            {
                "name": "replaceWithObject",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "objectName"
                    }
                ]
            },
            {
                "name": "showIP4Mapping",
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
                "name": "z_BETA_summarize",
                "help": null,
                "args": false
            }
        ],
        "service": [
            {
                "name": "addObjectWhereUsed",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "objectName"
                    }
                ]
            },
            {
                "name": "delete",
                "help": null,
                "args": false
            },
            {
                "name": "deleteForce",
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
                "name": "display",
                "help": null,
                "args": false
            },
            {
                "name": "displayReferences",
                "help": null,
                "args": false
            },
            {
                "name": "exportToExcel",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "filename"
                    },
                    {
                        "type": "pipeSeparatedList",
                        "subtype": "string",
                        "default": "*NONE*",
                        "choices": [
                            "WhereUsed",
                            "UsedInLocation"
                        ],
                        "help": "pipe(|) separated list of additional field to include in the report. The following is available:\n  - WhereUsed : list places where object is used (rules, groups ...)\n  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n",
                        "name": "additionalFields"
                    }
                ]
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
                        "default": "skipIfConflict",
                        "choices": [
                            "skipIfConflict",
                            "removeIfMatch",
                            "removeIfNumericalMatch"
                        ],
                        "name": "mode"
                    }
                ]
            },
            {
                "name": "name-addPrefix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "prefix"
                    }
                ]
            },
            {
                "name": "name-addSuffix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "suffix"
                    }
                ]
            },
            {
                "name": "name-removePrefix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "prefix"
                    }
                ]
            },
            {
                "name": "name-removeSuffix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "suffix"
                    }
                ]
            },
            {
                "name": "name-Rename",
                "help": "",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "This string is used to compose a name. You can use the following aliases :\n  - \\$$current.name\\$\\$ : current name of the object\n  - \\$$destinationport\\$\\$ : destination Port\n  - \\$$protocol\\$\\$ : service protocol\n  - \\$$sourceport\\$\\$ : source Port\n  - \\$$value\\$\\$ : value of the object\n",
                        "name": "stringFormula"
                    }
                ]
            },
            {
                "name": "removeWhereUsed",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "delete",
                        "choices": [
                            "delete",
                            "disable",
                            "setAny"
                        ],
                        "name": "actionIfLastMemberInRule"
                    }
                ]
            },
            {
                "name": "replaceByMembersAndDelete",
                "help": null,
                "args": false
            },
            {
                "name": "replaceGroupByService",
                "help": null,
                "args": false
            },
            {
                "name": "replaceWithObject",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "objectName"
                    }
                ]
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
            }
        ],
        "tag": [
            {
                "name": "Color-set",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "choices": [
                            "none",
                            "red",
                            "green",
                            "blue",
                            "yellow",
                            "copper",
                            "orange",
                            "purple",
                            "gray",
                            "light green",
                            "cyan",
                            "light gray",
                            "blue gray",
                            "lime",
                            "black",
                            "gold",
                            "brown",
                            "dark green"
                        ],
                        "name": "color"
                    }
                ]
            },
            {
                "name": "Comments-add",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "comments"
                    }
                ]
            },
            {
                "name": "Comments-delete",
                "help": null,
                "args": false
            },
            {
                "name": "delete",
                "help": null,
                "args": false
            },
            {
                "name": "deleteForce",
                "help": null,
                "args": false
            },
            {
                "name": "display",
                "help": null,
                "args": false
            },
            {
                "name": "displayReferences",
                "help": null,
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
                        "default": "skipIfConflict",
                        "choices": [
                            "skipIfConflict",
                            "removeIfMatch"
                        ],
                        "name": "mode"
                    }
                ]
            },
            {
                "name": "name-addPrefix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "prefix"
                    }
                ]
            },
            {
                "name": "name-addSuffix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "suffix"
                    }
                ]
            },
            {
                "name": "name-removePrefix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "prefix"
                    }
                ]
            },
            {
                "name": "name-removeSuffix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "suffix"
                    }
                ]
            },
            {
                "name": "name-toLowerCase",
                "help": null,
                "args": false
            },
            {
                "name": "name-toUCWords",
                "help": null,
                "args": false
            },
            {
                "name": "name-toUpperCase",
                "help": null,
                "args": false
            }
        ]
    },
    "filters": {
        "rule": [
            {
                "name": "action",
                "help": null,
                "operators": [
                    {
                        "name": "is.allow",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.deny",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.negative",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "app",
                "help": null,
                "operators": [
                    {
                        "name": "category.is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "characteristic.has",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "custom.has.signature",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "has",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.nocase",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "included-in.full.or.partial",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "included-in.full.or.partial.nocase",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "includes.full.or.partial",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "includes.full.or.partial.nocase",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.any",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "risk.is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "subcategory.is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "technology.is",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "description",
                "help": null,
                "operators": [
                    {
                        "name": "is.empty",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "dnathost",
                "help": null,
                "operators": [
                    {
                        "name": "has",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "included-in.full",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "included-in.full.or.partial",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "included-in.partial",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "includes.full",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "includes.full.or.partial",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "includes.partial",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "dst",
                "help": null,
                "operators": [
                    {
                        "name": "has",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.from.query",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.only",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.recursive",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.recursive.from.query",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.recursive.regex",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "included-in.full",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "included-in.full.or.partial",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "included-in.partial",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "includes.full",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "includes.full.or.partial",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "includes.partial",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.any",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.fully.included.in.list",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.negated",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.partially.included.in.list",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.partially.or.fully.included.in.list",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "dst-interface",
                "help": null,
                "operators": [
                    {
                        "name": "is.set",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "from",
                "help": null,
                "operators": [
                    {
                        "name": "has",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.only",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.regex",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.any",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "from.count",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "location",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches the one specified in argument",
                        "argument": "*required*"
                    },
                    {
                        "name": "is.child.of",
                        "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is child the one specified in argument",
                        "argument": "*required*"
                    },
                    {
                        "name": "regex",
                        "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches the regular expression specified in argument",
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "log",
                "help": null,
                "operators": [
                    {
                        "name": "at.end",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "at.start",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "logprof",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": "return true if Log Forwarding Profile is the one specified in argument",
                        "argument": "*required*"
                    },
                    {
                        "name": "is.set",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "name",
                "help": null,
                "operators": [
                    {
                        "name": "contains",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "eq",
                        "help": "returns TRUE if rule name matches the one specified in argument",
                        "argument": "*required*"
                    },
                    {
                        "name": "eq.nocase",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.in.file",
                        "help": "returns TRUE if rule name matches one of the names found in text file provided in argument",
                        "argument": "*required*"
                    },
                    {
                        "name": "regex",
                        "help": "returns TRUE if rule name matches the regular expression provided in argument",
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "rule",
                "help": null,
                "operators": [
                    {
                        "name": "has.destination.nat",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "has.source.nat",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.bidir.nat",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.disabled",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.dsri",
                        "help": "return TRUE if Disable Server Response Inspection has been enabled",
                        "argument": null
                    },
                    {
                        "name": "is.interzone",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.intrazone",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.postrule",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.prerule",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.universal",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.unused.fast",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "secprof",
                "help": null,
                "operators": [
                    {
                        "name": "as-profile.is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "as-profile.is.set",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "av-profile.is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "av-profile.is.set",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "data-profile.is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "data-profile.is.set",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "file-profile.is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "file-profile.is.set",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "group.is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.group",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.profile",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.set",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "not.set",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "type.is.group",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "type.is.profile",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "url-profile.is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "url-profile.is.set",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "vuln-profile.is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "vuln-profile.is.set",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "wf-profile.is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "wf-profile.is.set",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "service",
                "help": null,
                "operators": [
                    {
                        "name": "has",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.from.query",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.only",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.recursive",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.recursive.from.query",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.regex",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.value",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.value.recursive",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.any",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.application-default",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.tcp",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.tcp.only",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.udp",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.udp.only",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "snat",
                "help": null,
                "operators": [
                    {
                        "name": "is.dynamic-ip",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.dynamic-ip-and-port",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.static",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "snathost",
                "help": null,
                "operators": [
                    {
                        "name": "has",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "src",
                "help": null,
                "operators": [
                    {
                        "name": "has",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.from.query",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.only",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.recursive",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.recursive.from.query",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.recursive.regex",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "included-in.full",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "included-in.full.or.partial",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "included-in.partial",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "includes.full",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "includes.full.or.partial",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "includes.partial",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.any",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.fully.included.in.list",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.negated",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.partially.included.in.list",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.partially.or.fully.included.in.list",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "tag",
                "help": null,
                "operators": [
                    {
                        "name": "has",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.nocase",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "tag.count",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "target",
                "help": null,
                "operators": [
                    {
                        "name": "has",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.any",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "to",
                "help": null,
                "operators": [
                    {
                        "name": "has",
                        "help": "returns TRUE if field TO is using zone mentionned in argument. Ie: \"(to has Untrust)\"",
                        "argument": "*required*"
                    },
                    {
                        "name": "has.only",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.regex",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.any",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "to.count",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "url.category",
                "help": null,
                "operators": [
                    {
                        "name": "has",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.any",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "user",
                "help": null,
                "operators": [
                    {
                        "name": "has",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.regex",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.any",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.known",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.prelogon",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.unknown",
                        "help": null,
                        "argument": null
                    }
                ]
            }
        ],
        "address": [
            {
                "name": "description",
                "help": null,
                "operators": [
                    {
                        "name": "regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "location",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "members.count",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "name",
                "help": null,
                "operators": [
                    {
                        "name": "contains",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "eq",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "eq.nocase",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.in.file",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "netmask",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "object",
                "help": null,
                "operators": [
                    {
                        "name": "is.fqdn",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.group",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.ip-netmask",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.ip-range",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.member.of",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.recursive.member.of",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.tmp",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.unused",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.unused.recursive",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "overriden.at.lower.level",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "overrides.upper.level",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "refcount",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "reflocation",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.only",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "refstore",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "reftype",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "tag",
                "help": null,
                "operators": [
                    {
                        "name": "has",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.nocase",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "tag.count",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "value",
                "help": null,
                "operators": [
                    {
                        "name": "ip4.included-in",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "ip4.includes-full",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "ip4.includes-full-or-partial",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "ip4.match.exact",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "string.eq",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            }
        ],
        "service": [
            {
                "name": "description",
                "help": null,
                "operators": [
                    {
                        "name": "regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "location",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "members.count",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "name",
                "help": null,
                "operators": [
                    {
                        "name": "contains",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "eq",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "eq.nocase",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.in.file",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "object",
                "help": null,
                "operators": [
                    {
                        "name": "is.group",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.member.of",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.recursive.member.of",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.tcp",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.tmp",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.udp",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.unused",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.unused.recursive",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "refcount",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "reflocation",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.only",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "refstore",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "reftype",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "tag",
                "help": null,
                "operators": [
                    {
                        "name": "has",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.nocase",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "tag.count",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            }
        ],
        "tag": [
            {
                "name": "color",
                "help": null,
                "operators": [
                    {
                        "name": "eq",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "comments",
                "help": null,
                "operators": [
                    {
                        "name": "is.empty",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "location",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "name",
                "help": null,
                "operators": [
                    {
                        "name": "contains",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "eq",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "eq.nocase",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.in.file",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "object",
                "help": null,
                "operators": [
                    {
                        "name": "is.tmp",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.unused",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "refcount",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "reflocation",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.only",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "refstore",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "reftype",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            }
        ]
    }
};