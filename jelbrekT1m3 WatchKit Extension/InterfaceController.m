//
//  InterfaceController.m
//  jelbrekT1m3 WatchKit Extension
//
//  Created by tihmstar on 18.07.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#import "InterfaceController.h"
#include "jailbreak.h"
#include "offsetfinder.h"
#include <sys/utsname.h>
#include <sys/sysctl.h>

@interface InterfaceController ()

@end

double uptime(){
    struct timeval boottime;
    size_t len = sizeof(boottime);
    int mib[2] = { CTL_KERN, KERN_BOOTTIME };
    if( sysctl(mib, 2, &boottime, &len, NULL, 0) < 0 )
    {
        return -1.0;
    }
    time_t bsec = boottime.tv_sec, csec = time(NULL);
    
    return difftime(csec, bsec);
}

@implementation InterfaceController

- (void)awakeWithContext:(id)context {
    [super awakeWithContext:context];
    NSLog(@"did awake with context");
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(updateProgressFromNotification:) name:@"JB" object:nil];
    
    struct utsname ustruct = {};
    uname(&ustruct);
    printf("kern=%s\n",ustruct.version);
    if (strstr(ustruct.version,"MarijuanARM")){
        printf("already jelbroken!\n");
        [self.statusLabel setText:@"already jelbroken"];
        [self.jbButton setEnabled:FALSE];
        [self.jbButton setHidden:TRUE];
        return;
    }
    
    [self.statusLabel setText:@"It is not the right time, come back later"];
    [self.jbButton setEnabled:FALSE];
    [self.jbButton setHidden:TRUE];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0) ,^{
        int ut = 0;
        int waittime = 180;
        while ((ut = waittime - uptime()) > 0) {
            sleep(1);
        }
        dispatch_sync(dispatch_get_main_queue(), ^{
            [self.statusLabel setText:@"jelbrekTime"];
            [self.jbButton setHidden:FALSE];
            [self.jbButton setEnabled:TRUE];
        });
    });
}

- (void)willActivate {
    // This method is called when watch view controller is about to be visible to user
    [super willActivate];
    NSLog(@"willActivate");
    
}

- (void)didDeactivate {
    // This method is called when watch view controller is no longer visible
    [super didDeactivate];
}

-(void)updateProgressFromNotification:(id)sender{
    dispatch_async(dispatch_get_main_queue(), ^(void){
        NSString *prog=[sender userInfo][@"JBProgress"];
        NSLog(@"Progress: %@",prog);
        self.statusLabel.text = prog;
    });
}

- (IBAction)jelbrekPressed {
    NSLog(@"Start...");
    struct utsname ustruct = {};
    uname(&ustruct);
    printf("kern=%s\n",ustruct.version);
    if (!info_to_target_environment(ustruct.version)){
        printf("Error can't find offsets!\n");
        [self.statusLabel setText:@"u haz offsets??"];
        [self.jbButton setEnabled:FALSE];
        [self.jbButton setHidden:TRUE];
        return;
    }
    [self.jbButton setEnabled:FALSE];
    [self.jbButton setHidden:TRUE];
    [self.statusLabel setText:@"jelbreking..."];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0) ,^{
        sleep(1);
        jailbreak();
        dispatch_sync(dispatch_get_main_queue(), ^{
            [self.statusLabel setText:@"jelbrek done!"];
            NSLog(@"Done!");
        });
    });
    
}
@end



